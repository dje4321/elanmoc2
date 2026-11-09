/*
 * Driver for ELAN Match-On-Chip sensors
 * Copyright (C) 2021-2023 Davide Depau <davide@depau.eu>
 *
 * Based on original reverse-engineering work by Davide Depau. The protocol has
 * been reverse-engineered from captures of the official Windows driver, and by
 * testing commands on the sensor with a multiplatform Python prototype driver:
 * https://github.com/depau/Elan-Fingerprint-0c4c-PoC/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "elanmoc2"

// Library includes
#include <glib.h>
#include <sys/param.h>

// Local includes
#include "drivers_api.h"

#include "elanmoc2.h"

struct _FpiDeviceElanMoC2
{
  FpDevice parent;

  /* Device properties */
  unsigned int dev_type;

  /* USB response data */
  GBytes            *buffer_in;
  const Elanmoc2Cmd *in_flight_cmd;

  /* Command status data */
  FpiSsm      *ssm;
  unsigned int enrolled_num;
  unsigned int enrolled_num_retries;
  unsigned int print_index;
  GPtrArray   *list_result;

  // Enroll
  int      enroll_stage;
  FpPrint *enroll_print;
};

G_DEFINE_TYPE (FpiDeviceElanMoC2, fpi_device_elanmoc2, FP_TYPE_DEVICE);


static void
elanmoc2_cmd_usb_callback (FpiUsbTransfer *transfer,
                           FpDevice       *device,
                           gpointer        user_data,
                           GError         *error)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);
  gboolean short_is_error = (gboolean) (uintptr_t) user_data;

  if (self->ssm == NULL)
    {
      if (self->in_flight_cmd == NULL || !self->in_flight_cmd->ssm_not_required)
        fp_warn ("Received USB callback with no ongoing action");

      self->in_flight_cmd = NULL;

      if (error)
        {
          fp_info ("USB callback error: %s", error->message);
          g_error_free (error);
        }
      return;
    }

  if (error)
    {
      fpi_ssm_mark_failed (g_steal_pointer (&self->ssm),
                           g_steal_pointer (&error));
      return;
    }

  if (self->in_flight_cmd != NULL)
    {
      /* Send callback */
      const Elanmoc2Cmd *cmd = g_steal_pointer (&self->in_flight_cmd);

      if (cmd->in_len == 0)
        {
          /* Nothing to receive */
          fpi_ssm_next_state (self->ssm);
          return;
        }

      FpiUsbTransfer *transfer_in = fpi_usb_transfer_new (device);

      transfer_in->short_is_error = short_is_error;

      fpi_usb_transfer_fill_bulk (transfer_in, cmd->ep_in,
                                  cmd->in_len);

      g_autoptr(GCancellable) cancellable =
        cmd->cancellable ? fpi_device_get_cancellable (device) : NULL;

      fpi_usb_transfer_submit (transfer_in,
                               ELANMOC2_USB_RECV_TIMEOUT,
                               g_steal_pointer (&cancellable),
                               elanmoc2_cmd_usb_callback,
                               NULL);
    }
  else
    {
      /* Receive callback */
      if (transfer->actual_length > 0 && transfer->buffer[0] != 0x40)
        {
          fpi_ssm_mark_failed (g_steal_pointer (&self->ssm),
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "Error receiving data "
                                                         "from sensor"));
        }
      else
        {
          g_assert_null (self->buffer_in);
          self->buffer_in =
            g_bytes_new_take (g_steal_pointer (&(transfer->buffer)),
                              transfer->actual_length);
          fpi_ssm_next_state (self->ssm);
        }
    }
}

static void
elanmoc2_cmd_transceive_full (FpDevice          *device,
                              const Elanmoc2Cmd *cmd,
                              GByteArray        *buffer_out,
                              gboolean           short_is_error
                             )
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  g_assert (buffer_out->len == cmd->out_len);
  g_assert_null (self->in_flight_cmd);
  self->in_flight_cmd = cmd;

  g_autoptr(FpiUsbTransfer) transfer_out = fpi_usb_transfer_new (device);
  transfer_out->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (transfer_out,
                                   ELANMOC2_EP_CMD_OUT,
                                   g_byte_array_steal (buffer_out, NULL),
                                   cmd->out_len,
                                   g_free);

  g_autoptr(GCancellable) cancellable =
    cmd->cancellable ? fpi_device_get_cancellable (device) : NULL;

  fpi_usb_transfer_submit (g_steal_pointer (&transfer_out),
                           ELANMOC2_USB_SEND_TIMEOUT,
                           g_steal_pointer (&cancellable),
                           elanmoc2_cmd_usb_callback,
                           (gpointer) (uintptr_t) short_is_error);
}

static void
elanmoc2_cmd_transceive (FpDevice          *device,
                         const Elanmoc2Cmd *cmd,
                         GByteArray        *buffer_out)
{
  elanmoc2_cmd_transceive_full (device, cmd, buffer_out, TRUE);
}

static GByteArray *
elanmoc2_prepare_cmd (FpiDeviceElanMoC2 *self, const Elanmoc2Cmd *cmd)
{
  if (cmd->devices != ELANMOC2_ALL_DEV && !(cmd->devices & self->dev_type))
    return NULL;

  g_assert (cmd->out_len > 0);

  GByteArray *buffer = g_byte_array_new ();
  g_byte_array_set_size (buffer, cmd->out_len);
  memset (buffer->data, 0, buffer->len);

  buffer->data[0] = 0x40;
  memcpy (&buffer->data[1], cmd->cmd, cmd->is_single_byte_command ? 1 : 2);

  return buffer;
}

static void
elanmoc2_print_set_data (FpPrint      *print,
                         guchar        finger_id,
                         guchar        user_id_len,
                         const guchar *user_id)
{
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);

  GVariant *user_id_v = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                   user_id, user_id_len,
                                                   sizeof (guchar));
  GVariant *fpi_data = g_variant_new ("(y@ay)", finger_id, user_id_v);
  g_object_set (print, "fpi-data", fpi_data, NULL);
}

static GBytes *
elanmoc2_print_get_data (FpPrint *print,
                         guchar  *finger_id)
{
  g_autoptr(GVariant) fpi_data = NULL;
  g_autoptr(GVariant) user_id_v = NULL;

  g_object_get (print, "fpi-data", &fpi_data, NULL);
  g_assert_nonnull (fpi_data);

  g_variant_get (fpi_data, "(y@ay)", finger_id, &user_id_v);
  g_assert_nonnull (user_id_v);

  gsize user_id_len_s = 0;
  gconstpointer user_id_tmp = g_variant_get_fixed_array (user_id_v,
                                                         &user_id_len_s,
                                                         sizeof (guchar));
  g_assert (user_id_len_s <= 255);

  g_autoptr(GByteArray) user_id = g_byte_array_new ();
  g_byte_array_append (user_id, user_id_tmp, user_id_len_s);

  return g_byte_array_free_to_bytes (g_steal_pointer (&user_id));
}

static FpPrint *
elanmoc2_print_new_with_user_id (FpiDeviceElanMoC2 *self,
                                 guchar             finger_id,
                                 guchar             user_id_len,
                                 const guchar      *user_id)
{
  FpPrint *print = fp_print_new (FP_DEVICE (self));

  elanmoc2_print_set_data (print, finger_id, user_id_len, user_id);
  return g_steal_pointer (&print);
}

static guint
elanmoc2_get_user_id_max_length (FpiDeviceElanMoC2 *self)
{
  return self->dev_type == ELANMOC2_DEV_0C5E ?
         ELANMOC2_USER_ID_MAX_LEN_0C5E :
         ELANMOC2_USER_ID_MAX_LEN;
}

static GBytes *
elanmoc2_get_user_id_string (FpiDeviceElanMoC2 *self,
                             GBytes            *finger_info_response)
{
  GByteArray *user_id = g_byte_array_new ();

  guint offset = self->dev_type == ELANMOC2_DEV_0C5E ? 3 : 2;
  guint max_len = MIN (elanmoc2_get_user_id_max_length (self),
                       g_bytes_get_size (finger_info_response) - offset);

  g_byte_array_set_size (user_id, max_len);

  /* The string must be copied since the input data is not guaranteed to be
   * null-terminated */
  const guint8 *data = g_bytes_get_data (finger_info_response, NULL);
  memcpy (user_id->data, &data[offset], max_len);
  user_id->data[max_len] = '\0';

  return g_byte_array_free_to_bytes (user_id);
}

static FpPrint *
elanmoc2_print_new_from_finger_info (FpiDeviceElanMoC2 *self,
                                     guint8             finger_id,
                                     GBytes            *finger_info_resp)
{
  g_autoptr(GBytes) user_id = elanmoc2_get_user_id_string (self,
                                                           finger_info_resp);
  guint8 user_id_len = g_bytes_get_size (user_id);
  const char *user_id_data = g_bytes_get_data (user_id, NULL);

  if (g_str_has_prefix ( user_id_data, "FP"))
    {
      user_id_len = strnlen (user_id_data, user_id_len);
      fp_info ("Creating new print: finger %d, user id[%d]: %s",
               finger_id,
               user_id_len,
               (char *) user_id_data);
    }
  else
    {
      fp_info ("Creating new print: finger %d, user id[%d]: raw data",
               finger_id,
               user_id_len);
    }

  FpPrint *print =
    elanmoc2_print_new_with_user_id (self,
                                     finger_id,
                                     user_id_len,
                                     (const guint8 *) user_id_data);

  if (!fpi_print_fill_from_user_id (print, (const char *) user_id_data))
    /* Fingerprint matched with on-sensor print, but the on-sensor print was
     * not added by libfprint. Wipe it and report a failure. */
    fp_info ("Finger info not generated by libfprint");
  else
    fp_info ("Finger info with libfprint user ID");

  return g_steal_pointer (&print);
}

static gboolean
elanmoc2_finger_info_is_present (FpiDeviceElanMoC2 *self,
                                 GBytes            *finger_info_response)
{
  int offset = self->dev_type == ELANMOC2_DEV_0C5E ? 3 : 2;

  g_assert (g_bytes_get_size (finger_info_response) >= offset + 2);


  /* If the user ID starts with "FP", report true. This is a heuristic: after
   * wiping the sensor, the user IDs are not reset. */
  const gchar *data = g_bytes_get_data (finger_info_response, NULL);
  const gchar *user_id = &data[offset];

  /* I'm intentionally not using `g_str_has_prefix` here because it uses
   * `strlen` and this is binary data. */
  return memcmp (user_id, "FP", 2) == 0;
}


static void
elanmoc2_cancel (FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  fp_info ("Cancelling any ongoing requests");

  g_autoptr(GByteArray) buffer_out = elanmoc2_prepare_cmd (self, &cmd_abort);
  elanmoc2_cmd_transceive (device, &cmd_abort, buffer_out);
}

static void
elanmoc2_open (FpDevice *device)
{
  g_autoptr(GError) error = NULL;
  FpiDeviceElanMoC2 *self;

  if (!g_usb_device_reset (fpi_device_get_usb_device (device), &error))
    return fpi_device_open_complete (device, g_steal_pointer (&error));

  if (!g_usb_device_claim_interface (
        fpi_device_get_usb_device (FP_DEVICE (device)), 0, 0, &error))
    return fpi_device_open_complete (device, g_steal_pointer (&error));

  self = FPI_DEVICE_ELANMOC2 (device);
  self->dev_type = fpi_device_get_driver_data (FP_DEVICE (device));
  fpi_device_open_complete (device, NULL);
}

static void
elanmoc2_close (FpDevice *device)
{
  g_autoptr(GError) error = NULL;

  fp_info ("Closing device");
  elanmoc2_cancel (device);
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (device)),
                                  0, 0, &error);
  fpi_device_close_complete (device, g_steal_pointer (&error));
}

static void
elanmoc2_ssm_completed_callback (FpiSsm *ssm, FpDevice *device, GError *error)
{
  if (error)
    fpi_device_action_error (device, error);
}

static void
elanmoc2_perform_get_num_enrolled (FpiDeviceElanMoC2 *self, FpiSsm *ssm)
{
  self->enrolled_num_retries++;
  g_autoptr(GByteArray) buffer_out =
    elanmoc2_prepare_cmd (self,
                          &cmd_get_enrolled_count);

  if (buffer_out == NULL)
    {
      fpi_ssm_next_state (ssm);
      return;
    }

  fp_info ("Querying number of enrolled fingers");

  elanmoc2_cmd_transceive_full (FP_DEVICE (self),
                                &cmd_get_enrolled_count,
                                buffer_out,
                                false);
  fp_info ("Sent query for number of enrolled fingers");
}

static GError *
elanmoc2_get_num_enrolled_retry_or_error (FpiDeviceElanMoC2 *self,
                                          FpiSsm            *ssm,
                                          int                retry_state)
{
  fp_info ("Device returned no data, retrying");
  if (self->enrolled_num_retries >= ELANMOC2_MAX_RETRIES)
    return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                     "Device refused to respond to query for "
                                     "number of enrolled fingers");
  fpi_ssm_jump_to_state (ssm, retry_state);
  return NULL;
}

/**
 * elanmoc2_get_finger_error:
 * @self: #FpiDeviceElanMoC2 pointer
 * @out_can_retry: Whether the current action should be retried (out)
 *
 * Checks a command status code and, if an error has occurred, creates a new
 * error object. Returns whether the operation needs to be retried.
 *
 * Returns: #GError if failed, or %NULL
 */
static GError *
elanmoc2_get_finger_error (GBytes *buffer_in, gboolean *out_can_retry)
{
  g_assert_nonnull (buffer_in);
  g_assert (g_bytes_get_size (buffer_in) >= 2);

  const guint8 *data_in = g_bytes_get_data (buffer_in, NULL);

  /* Regular status codes never have the most-significant nibble set;
   * errors do */
  if ((data_in[1] & 0xF0) == 0)
    {
      *out_can_retry = TRUE;
      return NULL;
    }
  switch ((unsigned char) data_in[1])
    {
    case ELANMOC2_RESP_MOVE_DOWN:
      *out_can_retry = TRUE;
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_CENTER_FINGER,
                                       "Move your finger slightly downwards");

    case ELANMOC2_RESP_MOVE_RIGHT:
      *out_can_retry = TRUE;
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_CENTER_FINGER,
                                       "Move your finger slightly to the right");

    case ELANMOC2_RESP_MOVE_UP:
      *out_can_retry = TRUE;
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_CENTER_FINGER,
                                       "Move your finger slightly upwards");

    case ELANMOC2_RESP_MOVE_LEFT:
      *out_can_retry = TRUE;
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_CENTER_FINGER,
                                       "Move your finger slightly to the left");

    case ELANMOC2_RESP_SENSOR_DIRTY:
      *out_can_retry = TRUE;
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                       "Sensor is dirty or wet");

    case ELANMOC2_RESP_NOT_ENOUGH_SURFACE:
      *out_can_retry = TRUE;
      return fpi_device_retry_new_msg (FP_DEVICE_RETRY_REMOVE_FINGER,
                                       "Press your finger slightly harder on "
                                       "the sensor");

    case ELANMOC2_RESP_NOT_ENROLLED:
      *out_can_retry = FALSE;
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                       "Finger not recognized");

    case ELANMOC2_RESP_MAX_ENROLLED_REACHED:
      *out_can_retry = FALSE;
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_FULL,
                                       "Maximum number of fingers already "
                                       "enrolled");

    default:
      *out_can_retry = FALSE;
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                       "Unknown error");
    }
}

static void
elanmoc2_identify_verify_complete (FpDevice *device, GError *error)
{
  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY)
    fpi_device_identify_complete (device, error);
  else
    fpi_device_verify_complete (device, error);
}

/**
 * elanmoc2_identify_verify_report:
 * @device: #FpDevice
 * @print: Identified fingerprint
 * @error: Optional error
 *
 * Calls the correct verify or identify report function based on the input data.
 * Returns whether the action should be completed.
 *
 * Returns: Whether to complete the action.
 */
static gboolean
elanmoc2_identify_verify_report (FpDevice *device, FpPrint *print,
                                 GError **error)
{
  if (*error != NULL && (*error)->domain != FP_DEVICE_RETRY)
    return TRUE;

  if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_IDENTIFY)
    {
      if (print != NULL)
        {
          GPtrArray * gallery = NULL;
          fpi_device_get_identify_data (device, &gallery);

          for (int i = 0; i < gallery->len; i++)
            {
              FpPrint *to_match = g_ptr_array_index (gallery, i);
              if (fp_print_equal (to_match, print))
                {
                  fp_info ("Identify: finger matches");
                  fpi_device_identify_report (device,
                                              g_steal_pointer (&to_match),
                                              print,
                                              NULL);
                  return TRUE;
                }
            }
          fp_info ("Identify: no match");
        }
      fpi_device_identify_report (device, NULL, NULL, g_steal_pointer (error));
      return TRUE;
    }
  else
    {
      FpiMatchResult result = FPI_MATCH_FAIL;
      if (print != NULL)
        {
          FpPrint *to_match = NULL;
          fpi_device_get_verify_data (device, &to_match);
          g_assert_nonnull (to_match);

          if (fp_print_equal (to_match, print))
            {
              fp_info ("Verify: finger matches");
              result = FPI_MATCH_SUCCESS;
            }
          else
            {
              fp_info ("Verify: finger does not match");
              print = NULL;
            }
        }
      fpi_device_verify_report (device, result, print, g_steal_pointer (error));
      return result != FPI_MATCH_FAIL;
    }
}

static void
elanmoc2_identify_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) buffer_in = g_steal_pointer (&self->buffer_in);

  const guint8 *data_in =
    buffer_in != NULL ? g_bytes_get_data (buffer_in, NULL) : NULL;
  const gsize data_in_len =
    buffer_in != NULL ? g_bytes_get_size (buffer_in) : 0;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case IDENTIFY_GET_NUM_ENROLLED: {
        elanmoc2_perform_get_num_enrolled (self, ssm);
        break;
      }

    case IDENTIFY_CHECK_NUM_ENROLLED: {
        if (data_in_len == 0)
          {
            error =
              elanmoc2_get_num_enrolled_retry_or_error (self,
                                                        ssm,
                                                        IDENTIFY_GET_NUM_ENROLLED);
            if (error != NULL)
              {
                elanmoc2_identify_verify_complete (device,
                                                   g_steal_pointer (&error));
                fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
              }
            break;
          }

        g_assert_nonnull (data_in);
        g_assert (data_in_len >= 2);

        self->enrolled_num = data_in[1];

        if (self->enrolled_num == 0)
          {
            fp_info ("No fingers enrolled, no need to identify finger");
            error = NULL;
            elanmoc2_identify_verify_report (device, NULL, &error);
            elanmoc2_identify_verify_complete (device, NULL);
            fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
            break;
          }
        fpi_ssm_next_state (ssm);
        break;
      }

    case IDENTIFY_IDENTIFY: {
        g_autoptr(GByteArray) buffer_out = elanmoc2_prepare_cmd (self,
                                                                 &cmd_identify);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        elanmoc2_cmd_transceive (device, &cmd_identify, buffer_out);
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
        fp_info ("Sent identification request");
        break;
      }

    case IDENTIFY_GET_FINGER_INFO: {
        g_assert_nonnull (buffer_in);
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);
        gboolean can_retry = FALSE;
        error = elanmoc2_get_finger_error (buffer_in, &can_retry);
        if (error != NULL)
          {
            fp_info ("Identify failed: %s", error->message);
            if (can_retry)
              {
                elanmoc2_identify_verify_report (device, NULL, &error);
                fpi_ssm_jump_to_state (ssm, IDENTIFY_IDENTIFY);
              }
            else
              {
                elanmoc2_identify_verify_complete (device,
                                                   g_steal_pointer (&error));
                fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
              }
            break;
          }

        g_assert_nonnull (data_in);
        g_assert (data_in_len >= 2);

        self->print_index = data_in[1];

        fp_info ("Identified finger %d; requesting finger info",
                 self->print_index);

        g_autoptr(GByteArray) buffer_out =
          elanmoc2_prepare_cmd (self, &cmd_finger_info);

        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        g_assert (buffer_out->len >= 4);
        buffer_out->data[3] = self->print_index;
        elanmoc2_cmd_transceive (device, &cmd_finger_info, buffer_out);
        break;
      }

    case IDENTIFY_CHECK_FINGER_INFO: {
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);

        g_assert_nonnull (buffer_in);
        g_autoptr(FpPrint) print =
          elanmoc2_print_new_from_finger_info (self,
                                               self->print_index,
                                               buffer_in);

        error = NULL;
        elanmoc2_identify_verify_report (device,
                                         g_steal_pointer (&print),
                                         &error);
        elanmoc2_identify_verify_complete (device, g_steal_pointer (&error));
        fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
        break;
      }

    default:
      break;
    }
}

static void
elanmoc2_identify_verify (FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  fp_info ("[elanmoc2] New identify/verify operation");
  self->ssm = fpi_ssm_new (device, elanmoc2_identify_run_state,
                           IDENTIFY_NUM_STATES);
  self->enrolled_num_retries = 0;
  fpi_ssm_start (self->ssm, elanmoc2_ssm_completed_callback);
}

static void
elanmoc2_list_ssm_completed_callback (FpiSsm *ssm, FpDevice *device,
                                      GError *error)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  g_clear_pointer (&self->list_result, g_ptr_array_unref);
  elanmoc2_ssm_completed_callback (ssm, device, error);
}

static void
elanmoc2_list_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  g_autoptr(GBytes) buffer_in = g_steal_pointer (&self->buffer_in);

  const guint8 *data_in =
    buffer_in != NULL ? g_bytes_get_data (buffer_in, NULL) : NULL;
  const gsize data_in_len =
    buffer_in != NULL ? g_bytes_get_size (buffer_in) : 0;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case LIST_GET_NUM_ENROLLED:
      elanmoc2_perform_get_num_enrolled (self, ssm);
      break;

    case LIST_CHECK_NUM_ENROLLED: {
        if (data_in_len == 0)
          {
            g_autoptr(GError) error =
              elanmoc2_get_num_enrolled_retry_or_error (self,
                                                        ssm,
                                                        LIST_GET_NUM_ENROLLED);
            if (error != NULL)
              {
                fpi_device_list_complete (device,
                                          NULL,
                                          g_steal_pointer (&error));
                fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
              }
            break;
          }

        g_assert_nonnull (data_in);
        g_assert (data_in_len >= 2);

        self->enrolled_num = data_in[1];

        fp_info ("List: fingers enrolled: %d", self->enrolled_num);
        if (self->enrolled_num == 0)
          {
            fpi_device_list_complete (device,
                                      g_steal_pointer (&self->list_result),
                                      NULL);
            fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
            break;
          }
        self->print_index = 0;
        fpi_ssm_next_state (ssm);
        break;
      }

    case LIST_GET_FINGER_INFO: {
        g_autoptr(GByteArray) buffer_out =
          elanmoc2_prepare_cmd (self, &cmd_finger_info);

        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        g_assert (buffer_out->len >= 4);
        buffer_out->data[3] = self->print_index;
        elanmoc2_cmd_transceive_full (device,
                                      &cmd_finger_info,
                                      buffer_out,
                                      FALSE);
        fp_info ("Sent get finger info command for finger %d",
                 self->print_index);
        break;
      }

    case LIST_CHECK_FINGER_INFO:
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);

      if (data_in_len < cmd_finger_info.in_len)
        {
          GError *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                    "Reader refuses operation "
                                                    "before valid finger match");
          fpi_device_list_complete (device, NULL, error);
          fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
          break;
        }

      fp_info ("Successfully retrieved finger info for %d",
               self->print_index);
      g_assert_nonnull (buffer_in);
      if (elanmoc2_finger_info_is_present (self, buffer_in))
        {
          FpPrint *print = elanmoc2_print_new_from_finger_info (self,
                                                                self->print_index,
                                                                buffer_in);
          g_ptr_array_add (self->list_result, g_object_ref_sink (print));
        }

      self->print_index++;

      if (self->print_index < MIN (ELANMOC2_MAX_PRINTS, self->enrolled_num))
        {
          fpi_ssm_jump_to_state (ssm, LIST_GET_FINGER_INFO);
        }
      else
        {
          fpi_device_list_complete (device,
                                    g_steal_pointer (&self->list_result),
                                    NULL);
          fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
        }
      break;
    }
}

static void
elanmoc2_list (FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  fp_info ("[elanmoc2] New list operation");
  self->ssm = fpi_ssm_new (device, elanmoc2_list_run_state, LIST_NUM_STATES);
  self->list_result = g_ptr_array_new_with_free_func (g_object_unref);
  self->enrolled_num_retries = 0;
  fpi_ssm_start (self->ssm, elanmoc2_list_ssm_completed_callback);
}

static void
elanmoc2_enroll_ssm_completed_callback (FpiSsm *ssm, FpDevice *device,
                                        GError *error)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  /* Pointer is either stolen by fpi_device_enroll_complete() or otherwise
   * unref'd by libfprint elsewhere not in this driver. */
  self->enroll_print = NULL;
  elanmoc2_ssm_completed_callback (ssm, device, error);
}

static void
elanmoc2_enroll_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) buffer_in = g_steal_pointer (&self->buffer_in);

  const guint8 *data_in =
    buffer_in != NULL ? g_bytes_get_data (buffer_in, NULL) : NULL;
  const gsize data_in_len =
    buffer_in != NULL ? g_bytes_get_size (buffer_in) : 0;

  g_assert_nonnull (self->enroll_print);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    /* First check how many fingers are already enrolled */
    case ENROLL_GET_NUM_ENROLLED: {
        elanmoc2_perform_get_num_enrolled (self, ssm);
        break;
      }

    case ENROLL_CHECK_NUM_ENROLLED: {
        if (data_in_len == 0)
          {
            error =
              elanmoc2_get_num_enrolled_retry_or_error (self,
                                                        ssm,
                                                        ENROLL_GET_NUM_ENROLLED);
            if (error != NULL)
              {
                fpi_device_enroll_complete (device,
                                            NULL,
                                            g_steal_pointer (&error));
                fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
              }
            break;
          }

        g_assert_nonnull (data_in);
        g_assert (data_in_len >= 2);
        self->enrolled_num = data_in[1];

        if (self->enrolled_num >= ELANMOC2_MAX_PRINTS)
          {
            fp_info ("Can't enroll, sensor storage is full");
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_FULL,
                                              "Sensor storage is full");
            fpi_device_enroll_complete (device,
                                        NULL,
                                        g_steal_pointer (&error));
            fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
          }
        else if (self->enrolled_num == 0)
          {
            fp_info ("Enrolled count is 0, proceeding with enroll stage");
            fpi_ssm_jump_to_state (ssm, ENROLL_ENROLL);
          }
        else
          {
            fp_info ("Fingers enrolled: %d, need to check for re-enroll",
                     self->enrolled_num);
            fpi_ssm_next_state (ssm);
          }
        break;
      }

    case ENROLL_EARLY_REENROLL_CHECK: {
        g_autoptr(GByteArray) buffer_out = elanmoc2_prepare_cmd (self,
                                                                 &cmd_identify);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        elanmoc2_cmd_transceive (device, &cmd_identify, buffer_out);
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
        fp_info ("Sent identification request");
        break;
      }

    case ENROLL_GET_ENROLLED_FINGER_INFO: {
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

        g_assert_nonnull (data_in);
        g_assert (g_bytes_get_size (buffer_in) >= 2);

        /* Not enrolled - skip to enroll stage */
        if (data_in[1] == ELANMOC2_RESP_NOT_ENROLLED)
          {
            fp_info ("Finger not enrolled, proceeding with enroll stage");
            fpi_device_enroll_progress (device, self->enroll_stage, NULL,
                                        NULL);
            fpi_ssm_jump_to_state (ssm, ENROLL_ENROLL);
            break;
          }

        /* Identification failed (i.e. dirty) - retry */
        gboolean can_retry = FALSE;
        error = elanmoc2_get_finger_error (buffer_in, &can_retry);
        if (error != NULL)
          {
            fp_info ("Identify failed: %s", error->message);
            if (can_retry)
              {
                fpi_device_enroll_progress (device, self->enroll_stage, NULL,
                                            g_steal_pointer (&error));
                fpi_ssm_jump_to_state (ssm, ENROLL_EARLY_REENROLL_CHECK);
              }
            else
              {
                fpi_device_enroll_complete (device, NULL,
                                            g_steal_pointer (&error));
                fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
                self->enroll_print = NULL;
              }
            break;
          }

        /* Finger already enrolled - fetch finger info for deletion */
        self->print_index = data_in[1];
        fp_info ("Finger enrolled as %d; fetching finger info",
                 self->print_index);
        g_autoptr(GByteArray) buffer_out =
          elanmoc2_prepare_cmd (self, &cmd_finger_info);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        g_assert (buffer_out->len >= 4);
        buffer_out->data[3] = self->print_index;
        elanmoc2_cmd_transceive (device, &cmd_finger_info, buffer_out);
        break;
      }

    case ENROLL_ATTEMPT_DELETE: {
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
        fp_info ("Deleting enrolled finger %d", self->print_index);
        g_assert_nonnull (buffer_in);

        /* Attempt to delete the finger */
        g_autoptr(GBytes) user_id =
          elanmoc2_get_user_id_string (self, buffer_in);
        g_autoptr(GByteArray) buffer_out =
          elanmoc2_prepare_cmd (self, &cmd_delete);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        gsize user_id_bytes = MIN (cmd_delete.out_len - 4,
                                   ELANMOC2_USER_ID_MAX_LEN);
        g_assert (buffer_out->len >= 4 + user_id_bytes);
        buffer_out->data[3] = 0xf0 | (self->print_index + 5);
        memcpy (&buffer_out->data[4],
                g_bytes_get_data (user_id, NULL),
                user_id_bytes);
        elanmoc2_cmd_transceive (device, &cmd_delete, buffer_out);

        break;
      }

    case ENROLL_CHECK_DELETED: {
        g_assert_nonnull (data_in);
        g_assert (g_bytes_get_size (buffer_in) >= 2);

        if (data_in[1] != 0)
          {
            fp_info ("Failed to delete finger %d, wiping sensor",
                     self->print_index);
            fpi_ssm_jump_to_state (ssm, ENROLL_WIPE_SENSOR);
          }
        else
          {
            fp_info ("Finger %d deleted, proceeding with enroll stage",
                     self->print_index);
            self->enrolled_num--;
            fpi_device_enroll_progress (device, self->enroll_stage, NULL,
                                        NULL);
            fpi_ssm_jump_to_state (ssm, ENROLL_ENROLL);
          }
        break;
      }

    case ENROLL_WIPE_SENSOR: {
        g_autoptr(GByteArray) buffer_out =
          elanmoc2_prepare_cmd (self, &cmd_wipe_sensor);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        elanmoc2_cmd_transceive (device, &cmd_wipe_sensor, buffer_out);
        self->enrolled_num = 0;
        self->print_index = 0;
        fp_info (
          "Wipe sensor command sent - next operation will take a while");
        fpi_ssm_next_state (ssm);
        break;
      }

    case ENROLL_ENROLL: {
        g_autoptr(GByteArray) buffer_out = elanmoc2_prepare_cmd (self,
                                                                 &cmd_enroll);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        g_assert (buffer_out->len >= 7);
        buffer_out->data[3] = self->enrolled_num;
        buffer_out->data[4] = ELANMOC2_ENROLL_TIMES;
        buffer_out->data[5] = self->enroll_stage;
        buffer_out->data[6] = 0;
        elanmoc2_cmd_transceive (device, &cmd_enroll, buffer_out);
        fp_info ("Enroll command sent: %d/%d", self->enroll_stage,
                 ELANMOC2_ENROLL_TIMES);
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
        break;
      }

    case ENROLL_CHECK_ENROLLED: {
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_PRESENT);

        g_assert_nonnull (data_in);
        g_assert (g_bytes_get_size (buffer_in) >= 2);

        if (data_in[1] == 0)
          {
            /* Stage okay */
            fp_info ("Enroll stage succeeded");
            self->enroll_stage++;
            fpi_device_enroll_progress (device, self->enroll_stage,
                                        self->enroll_print, NULL);
            if (self->enroll_stage >= ELANMOC2_ENROLL_TIMES)
              {
                fp_info ("Enroll completed");
                fpi_ssm_next_state (ssm);
                break;
              }
          }
        else
          {
            /* Detection error */
            gboolean can_retry = FALSE;
            error = elanmoc2_get_finger_error (buffer_in, &can_retry);
            if (error != NULL)
              {
                fp_info ("Enroll stage failed: %s", error->message);
                if (data_in[1] == ELANMOC2_RESP_NOT_ENROLLED)
                  {
                    /* Not enrolled is a fatal error for "identify" but not for
                     * "enroll" */
                    error->domain = FP_DEVICE_RETRY;
                    error->code = FP_DEVICE_RETRY_TOO_SHORT;
                    can_retry = FALSE;
                  }
                if (can_retry)
                  {
                    fpi_device_enroll_progress (device, self->enroll_stage,
                                                NULL, g_steal_pointer (&error));
                  }
                else
                  {
                    fpi_device_enroll_complete (device, NULL,
                                                g_steal_pointer (&error));
                    fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
                  }
              }
            else
              {
                fp_info ("Enroll stage failed for unknown reasons");
              }
          }
        fp_info ("Performing another enroll");
        fpi_ssm_jump_to_state (ssm, ENROLL_ENROLL);
        break;
      }

    case ENROLL_LATE_REENROLL_CHECK: {
        fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
        g_autoptr(GByteArray) buffer_out =
          elanmoc2_prepare_cmd (self, &cmd_check_enroll_collision);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        elanmoc2_cmd_transceive (device, &cmd_check_enroll_collision, buffer_out);
        fp_info ("Check re-enroll command sent");
        break;
      }

    case ENROLL_COMMIT: {
        error = NULL;

        g_assert_nonnull (data_in);
        g_assert (g_bytes_get_size (buffer_in) >= 2);

        if (data_in[1] != 0)
          {
            fp_info ("Finger is already enrolled at position %d, cannot commit",
                     data_in[2]);
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_DUPLICATE,
                                              "Finger is already enrolled");
            fpi_device_enroll_complete (device, NULL,
                                        g_steal_pointer (&error));
            fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
            self->enroll_print = NULL;
            break;
          }

        fp_info ("Finger is not enrolled, committing");
        g_autoptr(GByteArray) buffer_out = elanmoc2_prepare_cmd (self,
                                                                 &cmd_commit);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }
        g_autofree gchar *user_id = fpi_print_generate_user_id (
          self->enroll_print);
        elanmoc2_print_set_data (self->enroll_print, self->enrolled_num,
                                 strlen (user_id), (guint8 *) user_id);

        g_assert (buffer_out->len == cmd_commit.out_len);
        buffer_out->data[3] = 0xf0 | (self->enrolled_num + 5);
        strncpy ((gchar *) &buffer_out->data[4], user_id, cmd_commit.out_len - 4);
        elanmoc2_cmd_transceive (device, &cmd_commit, buffer_out);
        fp_info ("Commit command sent");
        break;
      }

    case ENROLL_CHECK_COMMITTED: {
        error = NULL;

        g_assert_nonnull (data_in);
        g_assert (g_bytes_get_size (buffer_in) >= 2);

        if (data_in[1] != 0)
          {
            fp_info ("Commit failed with error code %d", data_in[1]);
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                              "Failed to store fingerprint for "
                                              "unknown reasons");
            fpi_device_enroll_complete (device, NULL, error);
            fpi_ssm_mark_failed (g_steal_pointer (&self->ssm),
                                 g_steal_pointer (&error));
          }
        else
          {
            fp_info ("Commit succeeded");
            fpi_device_enroll_complete (device,
                                        g_object_ref (self->enroll_print),
                                        NULL);
            fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
          }
        break;
      }
    }
}

static void
elanmoc2_enroll (FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  fp_info ("[elanmoc2] New enroll operation");

  self->enroll_stage = 0;
  fpi_device_get_enroll_data (device, &self->enroll_print);

  self->ssm = fpi_ssm_new (device, elanmoc2_enroll_run_state,
                           ENROLL_NUM_STATES);
  self->enrolled_num_retries = 0;
  fpi_ssm_start (self->ssm, elanmoc2_enroll_ssm_completed_callback);
}

static void
elanmoc2_delete_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) buffer_in = g_steal_pointer (&self->buffer_in);

  const guint8 *data_in =
    buffer_in != NULL ? g_bytes_get_data (buffer_in, NULL) : NULL;
  const gsize data_in_len =
    buffer_in != NULL ? g_bytes_get_size (buffer_in) : 0;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DELETE_GET_NUM_ENROLLED:
      elanmoc2_perform_get_num_enrolled (self, ssm);
      break;

    case DELETE_DELETE: {
        if (data_in_len == 0)
          {
            error =
              elanmoc2_get_num_enrolled_retry_or_error (self,
                                                        ssm,
                                                        DELETE_GET_NUM_ENROLLED);
            if (error != NULL)
              {
                fpi_device_delete_complete (device, g_steal_pointer (&error));
                fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
              }
            break;
          }

        g_assert_nonnull (data_in);
        g_assert (data_in_len >= 2);

        self->enrolled_num = data_in[1];
        if (self->enrolled_num == 0)
          {
            fp_info ("No fingers enrolled, nothing to delete");
            fpi_device_delete_complete (device, NULL);
            fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
            break;
          }
        FpPrint *print = NULL;
        fpi_device_get_delete_data (device, &print);

        guint8 finger_id = 0xFF;

        g_autoptr(GBytes) user_id =
          elanmoc2_print_get_data (print, &finger_id);
        gsize user_id_bytes = MIN (cmd_delete.out_len - 4,
                                   ELANMOC2_USER_ID_MAX_LEN);
        user_id_bytes = MIN (user_id_bytes, g_bytes_get_size (user_id));

        g_autoptr(GByteArray) buffer_out = elanmoc2_prepare_cmd (self,
                                                                 &cmd_delete);
        if (buffer_out == NULL)
          {
            fpi_ssm_next_state (ssm);
            break;
          }

        g_assert (buffer_out->len >= 4 + user_id_bytes);
        buffer_out->data[3] = 0xf0 | (finger_id + 5);
        memcpy (&buffer_out->data[4],
                g_bytes_get_data (user_id, NULL),
                user_id_bytes);
        elanmoc2_cmd_transceive (device, &cmd_delete, buffer_out);
        break;
      }

    case DELETE_CHECK_DELETED: {
        error = NULL;

        g_assert_nonnull (data_in);
        g_assert (data_in_len >= 2);

        /* If the finger is still enrolled, we don't want to fail the operation,
         * but we also don't want to report success. We'll just report that the
         * finger is no longer enrolled. */
        if (data_in[1] != 0 &&
            data_in[1] != ELANMOC2_RESP_NOT_ENROLLED)
          fp_info (
            "Delete failed with error code %d, assuming no longer enrolled",
            data_in[1]);

        fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
        fpi_device_delete_complete (device, g_steal_pointer (&error));

        break;
      }
    }
}

static void
elanmoc2_delete (FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  fp_info ("[elanmoc2] New delete operation");
  self->ssm = fpi_ssm_new (device, elanmoc2_delete_run_state,
                           DELETE_NUM_STATES);
  self->enrolled_num_retries = 0;
  fpi_ssm_start (self->ssm, elanmoc2_ssm_completed_callback);
}

static void
elanmoc2_clear_storage_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  g_autoptr(GByteArray) buffer_out = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GBytes) buffer_in = g_steal_pointer (&self->buffer_in);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CLEAR_STORAGE_WIPE_SENSOR:
      buffer_out = elanmoc2_prepare_cmd (self, &cmd_wipe_sensor);
      if (buffer_out == NULL)
        {
          fpi_ssm_next_state (ssm);
          break;
        }
      elanmoc2_cmd_transceive (device, &cmd_wipe_sensor, buffer_out);
      fp_info ("Sent sensor wipe command, sensor will hang for ~5 seconds");
      break;

    case CLEAR_STORAGE_GET_NUM_ENROLLED:
      elanmoc2_perform_get_num_enrolled (self, ssm);
      break;

    case CLEAR_STORAGE_CHECK_NUM_ENROLLED: {
        gsize buffer_in_len = g_bytes_get_size (buffer_in);

        if (buffer_in_len == 0)
          {
            error =
              elanmoc2_get_num_enrolled_retry_or_error (self,
                                                        ssm,
                                                        CLEAR_STORAGE_GET_NUM_ENROLLED);
            if (error != NULL)
              {
                fpi_device_clear_storage_complete (device, g_steal_pointer (&error));
                fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
              }
            break;
          }


        /* It should take around 5 seconds to arrive here after the wipe sensor
         * command */
        g_assert_nonnull (buffer_in);
        g_assert (buffer_in_len >= 2);

        const guint8 *data_in = g_bytes_get_data (buffer_in, NULL);
        self->enrolled_num = data_in[1];

        if (self->enrolled_num == 0)
          {
            fpi_device_clear_storage_complete (device, NULL);
            fpi_ssm_mark_completed (g_steal_pointer (&self->ssm));
          }
        else
          {
            error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                              "Sensor erase requested but "
                                              "storage is not empty");
            fpi_device_clear_storage_complete (device, error);
            fpi_ssm_mark_failed (g_steal_pointer (&self->ssm),
                                 g_steal_pointer (&error));
            break;
          }
        break;
      }
    }
}

static void
elanmoc2_clear_storage (FpDevice *device)
{
  FpiDeviceElanMoC2 *self = FPI_DEVICE_ELANMOC2 (device);

  fp_info ("[elanmoc2] New clear storage operation");
  self->ssm = fpi_ssm_new (device, elanmoc2_clear_storage_run_state,
                           CLEAR_STORAGE_NUM_STATES);
  self->enrolled_num_retries = 0;
  fpi_ssm_start (self->ssm, elanmoc2_ssm_completed_callback);
}

static void
fpi_device_elanmoc2_init (FpiDeviceElanMoC2 *self)
{
  G_DEBUG_HERE ();
}

static const FpIdEntry elanmoc2_id_table[] = {
  {.vid = ELANMOC2_VEND_ID, .pid = 0x0c00, .driver_data = ELANMOC2_ALL_DEV},
  {.vid = ELANMOC2_VEND_ID, .pid = 0x0c4c, .driver_data = ELANMOC2_ALL_DEV},
  {.vid = ELANMOC2_VEND_ID, .pid = 0x0c5e, .driver_data = ELANMOC2_DEV_0C5E},
  {.vid = 0, .pid = 0, .driver_data = 0}
};

static void
fpi_device_elanmoc2_class_init (FpiDeviceElanMoC2Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = FP_COMPONENT;
  dev_class->full_name = ELANMOC2_DRIVER_FULLNAME;

  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = elanmoc2_id_table;

  dev_class->nr_enroll_stages = ELANMOC2_ENROLL_TIMES;
  dev_class->temp_hot_seconds = -1;

  dev_class->open = elanmoc2_open;
  dev_class->close = elanmoc2_close;
  dev_class->identify = elanmoc2_identify_verify;
  dev_class->verify = elanmoc2_identify_verify;
  dev_class->enroll = elanmoc2_enroll;
  dev_class->delete = elanmoc2_delete;
  dev_class->clear_storage = elanmoc2_clear_storage;
  dev_class->list = elanmoc2_list;
  dev_class->cancel = elanmoc2_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_DUPLICATES_CHECK;
  dev_class->features |= FP_DEVICE_FEATURE_UPDATE_PRINT;
}
