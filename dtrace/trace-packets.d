#!/usr/sbin/dtrace -CZqs

#pragma D option bufsize=16k

/*
 * Constants used to pick out parts of SP responses.
 *
 * Packets are laid out as:
 *
 * [Header][Message][Trailing data]
 *
 * Header has:
 *
 * - 1 u8 for the version
 * - 1 u64 for the message ID
 * - 1 u8 for the message kind variant ID
 *
 * For 10 octets total.
 *
 * Message has:
 *
 * - 1 u8 for the version
 * - 1 u8 for the MessageBody variant ID
 *
 * For 2 octets total
 *
 * For the MessageBody::SpResponse, which we support printing on receipt, the
 * contents are:
 *
 * - 1 u8 for the variant ID (e.g., SpResponse::Read)
 * - 2 u64s for the successful and failed module IDs.
 *
 * For 17 octets total.
 */
#define HEADER_VERSION_OFFSET (0)
#define HEADER_MESSAGE_ID_OFFSET (1)
#define HEADER_MESSAGE_KIND_OFFSET (HEADER_MESSAGE_ID_OFFSET + 8)
#define MESSAGE_VERSION_OFFSET (HEADER_MESSAGE_KIND_OFFSET + 1)
#define MESSAGE_BODY_VARIANT_OFFSET (MESSAGE_VERSION_OFFSET + 1)
#define SP_RESPONSE_VARIANT_OFFSET (MESSAGE_BODY_VARIANT_OFFSET + 1)
#define SUCCESS_MODULE_ID_OFFSET (SP_RESPONSE_VARIANT_OFFSET + 1)
#define FAILED_MODULE_ID_OFFSET (SUCCESS_MODULE_ID_OFFSET + 8)

/*
 * Definitions of the `MessageKind` enum
 */
#define MESSAGE_KIND_ERROR (0)
#define MESSAGE_KIND_HOST_REQUEST (1)
#define MESSAGE_KIND_SP_RESPONSE (2)

/*
 * Definitions of the `SpResponse` enum discriminant.
 */
#define SP_RESPONSE_READ (0)
#define SP_RESPONSE_WRITE (1)
#define SP_RESPONSE_STATUS (2)
#define SP_RESPONSE_ACK (3)
#define SP_RESPONSE_EXTENDED_STATUS (6)

xcvr_ctl$target:::packet-sent
{
    this->peer = json(copyinstr(arg0), "ok");
    this->n_bytes = arg1;
    this->buf = (char*)copyin(arg2, this->n_bytes);
    this->vers = *(uint8_t*) this->buf;
    this->message_id = *(uint64_t*) (this->buf + HEADER_MESSAGE_ID_OFFSET);
    this->message_kind = *(uint8_t*) (this->buf + HEADER_MESSAGE_KIND_OFFSET);

    printf("Sent payload to %s\n", this->peer);
    printf("  n_bytes: %d\n", this->n_bytes);
    printf("  version: %d\n", this->vers);
    printf("  msg id: %d\n", this->message_id);

    this->message_kind_str = "Unknown";
    if (this->message_kind == MESSAGE_KIND_ERROR) {
        this->message_kind_str = "Error";
    } else if (this->message_kind == MESSAGE_KIND_HOST_REQUEST) {
        this->message_kind_str = "HostRequest";
    } else if (this->message_kind == MESSAGE_KIND_SP_RESPONSE) {
        this->message_kind_str = "SpResponse";
    }
    printf("  msg kind: %s (%d)\n", this->message_kind_str, this->message_kind);
}

/* "First" action on receiving a packet. Copy in the main metadata. */
xcvr-ctl$target:::packet-received
{
    this->peer = json(copyinstr(arg0), "ok");
    this->n_bytes = arg1;

    /* Pointer to the packet payload itself. */
    this->buf = (char*) copyin(arg2, this->n_bytes);
    this->vers = this->buf[0];
    this->message_id = *(uint64_t*) (this->buf + HEADER_MESSAGE_ID_OFFSET);
    this->message_kind = this->buf[HEADER_MESSAGE_KIND_OFFSET];
    printf("Recv payload from: %s\n", this->peer);
    printf("  Raw packet:\n");
    tracemem(this->buf, 128, this->n_bytes);
    printf("  n_bytes: %d\n", this->n_bytes);
    printf("  version: %d\n", this->vers);
    printf("  msg id: %d\n", this->message_id);
}

/* Print the MessageKinds */
xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_ERROR/
{
    printf("  msg kind: Error (%d)\n", this->message_kind);
}

xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_HOST_REQUEST/
{
    printf("  msg kind: HostRequest (%d)\n", this->message_kind);
}

xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_SP_RESPONSE/
{
    printf("  msg kind: SpResponse (%d)\n", this->message_kind);
    this->message_body_variant = this->buf[MESSAGE_BODY_VARIANT_OFFSET];
}

/* Print the SP response kind, note these are printed in order. */
xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_SP_RESPONSE &&
this->message_body_variant == SP_RESPONSE_STATUS/
{
    printf("MessageBody: Status (%d)\n", this->message_body_variant);
}

xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_SP_RESPONSE &&
this->message_body_variant == SP_RESPONSE_READ/
{
    printf("MessageBody: Read (%d)\n", this->message_body_variant);
}

xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_SP_RESPONSE &&
this->message_body_variant == SP_RESPONSE_WRITE/
{
    printf("MessageBody: Write (%d)\n", this->message_body_variant);
}

xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_SP_RESPONSE &&
this->message_body_variant == SP_RESPONSE_ACK/
{
    printf("MessageBody: Ack (%d)\n", this->message_body_variant);
}

xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_SP_RESPONSE &&
this->message_body_variant == SP_RESPONSE_EXTENDED_STATUS/
{
    printf("MessageBody: ExtendedStatus (%d)\n", this->message_body_variant);
}

/* Then print the module IDs and remaining data. */
xcvr-ctl$target:::packet-received
/this->message_kind == MESSAGE_KIND_SP_RESPONSE/
{
    this->success_modules = *(uint64_t*)(this->buf + SUCCESS_MODULE_ID_OFFSET);
    this->failed_modules = *(uint64_t*)(this->buf + FAILED_MODULE_ID_OFFSET);
    printf("  successful module IDs: 0x%08x\n", this->success_modules);
    printf("  failed module IDs:     0x%08x\n", this->failed_modules);
    this->n_octets = this->n_bytes - FAILED_MODULE_ID_OFFSET;
    this->data = (this->buf + FAILED_MODULE_ID_OFFSET);
    printf("  remaining data (up to %d octets):\n", this->n_octets);
    tracemem(this->data, 128, this->n_octets);
    printf("\n");
}
