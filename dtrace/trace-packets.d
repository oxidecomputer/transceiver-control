#!/usr/sbin/dtrace -CZqs

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
 * For 10 bytes total.
 *
 * Message has:
 *
 * - 1 u8 for the version
 * - 1 u8 for the MessageBody variant ID
 *
 * For 2 bytes total
 *
 * For an SpResponse::Status:
 *
 * - 1 u8 for the variant ID
 * - 2 u64s for the successful and failed module IDs.
 *
 * For 17 bytes total.
 *
 * So the data should start at:
 *
 * 10 + 2 + 17 = 29 octets into the message.
 */
#define HEADER_VERSION_OFFSET 0
#define HEADER_MESSAGE_ID_OFFSET (1)
#define HEADER_MESSAGE_KIND_OFFSET (9)
#define MESSAGE_VERSION_OFFSET (HEADER_MESSAGE_KIND_OFFSET + 1)
#define MESSAGE_BODY_VARIANT_OFFSET (MESSAGE_VERSION_OFFSET + 1)
#define SP_RESPONSE_VARIANT_OFFSET (MESSAGE_BODY_VARIANT_OFFSET + 1)
#define MODULE_ID_OFFSET (SP_RESPONSE_VARIANT_OFFSET + 1)
#define STATUS_DATA_OFFSET (MODULE_ID_OFFSET + 16)

#define MESSAGE_KIND_SP_RESPONSE 2
#define SP_RESPONSE_STATUS 2
#define SP_RESPONSE_ACK 3

xcvr-ctl$target:::packet-sent
{
	peer = json(copyinstr(arg0), "ok");
	n_bytes = arg1;
	buf = (char*)copyin(arg2, n_bytes);
	vers = *(uint8_t*) buf;
	message_id = *(uint64_t*) (buf + HEADER_MESSAGE_ID_OFFSET);
	message_kind = *(uint8_t*) (buf + HEADER_MESSAGE_KIND_OFFSET);

	printf("Sent payload to %s\n", peer);
	printf("  n_bytes: %d\n", n_bytes);
	printf("  version: %d\n", vers);
	printf("  msg id: %d\n", message_id);
	printf("  msg kind: %d\n", message_kind);
}

xcvr-ctl$target:::packet-received
{
	peer = json(copyinstr(arg0), "ok");
	n_bytes = arg1;

	/* Pointer to the packet payload itself. */
	buf = (char*) copyin(arg2, n_bytes);

	vers = buf[0];
	message_id = *(uint64_t*) (buf + HEADER_MESSAGE_ID_OFFSET);
	message_kind = buf[HEADER_MESSAGE_KIND_OFFSET];

	printf("Recv payload from: %s\n", peer);
	printf("  n_bytes: %d\n", n_bytes);
	printf("  version: %d\n", vers);
	printf("  msg id: %d\n", message_id);
	printf("  msg kind: %d\n", message_kind);

	/* Print SpResponse data, for certain kinds of messages */
	if (message_kind == MESSAGE_KIND_SP_RESPONSE) {
		message_body_variant = buf[MESSAGE_BODY_VARIANT_OFFSET];
		if (message_body_variant == MESSAGE_KIND_SP_RESPONSE) {
			sp_response_variant = buf[SP_RESPONSE_VARIANT_OFFSET];
			if ((sp_response_variant == SP_RESPONSE_STATUS) || (sp_response_variant == SP_RESPONSE_ACK))
            {
				printf("  module IDs:\n");
				tracemem(buf + MODULE_ID_OFFSET, 16);
				n_octets = n_bytes - STATUS_DATA_OFFSET;
				data = (buf + STATUS_DATA_OFFSET);
				printf("  data (up to %d octets): ", n_octets);
				tracemem(data, 64, n_octets);
			}
		}
	}
}
