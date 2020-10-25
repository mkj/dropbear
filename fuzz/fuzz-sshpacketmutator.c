#include "fuzz.h"

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

static void fuzz_get_packets(buffer *inp, buffer **out_packets, unsigned int *num_out_packets) {
    /* Skip any existing banner. Format is
          SSH-protoversion-softwareversion SP comments CR LF
    so we look for SSH-2. then a subsequent LF */
    unsigned char* version = memmem(inp->data, inp->len, "SSH-2.", strlen("SSH-2."));
    if (version) {
        buf_incrpos(inp, version - inp->data);
        unsigned char* newline = memchr(&inp->data[inp->pos], '\n', inp->len - inp->pos);
        if (newline) {
            buf_incrpos(inp, newline - &inp->data[inp->pos]);
        } else {
            /* Give up on any version string */
            buf_setpos(inp, 0);
        }
    }

    const unsigned int max_out_packets = *num_out_packets;
    *num_out_packets = 0;
    while (1) {
        if (inp->pos + 4 > inp->len) {
            /* End of input */
            break;
        }

        if (*num_out_packets >= max_out_packets) {
            /* End of output */
            break;
        }

        /* Read packet */
        unsigned int packet_len = buf_getint(inp);
        if (packet_len <= RECV_MAX_PACKET_LEN) {
            /* Bad length, try skipping a single byte */
            buf_decrpos(inp, 3);
            continue;
        }
        packet_len = MIN(packet_len, inp->len - inp->pos);

        /* Copy to output buffer */
        buffer* new_packet = buf_new(RECV_MAX_PACKET_LEN);
        buf_putint(new_packet, packet_len);
        buf_putbytes(new_packet, buf_getptr(inp, packet_len), packet_len);
        buf_incrpos(inp, packet_len);

        out_packets[*num_out_packets] = new_packet;
        (*num_out_packets)++;
    }

}

/* Mutate in-place */
void buf_llvm_mutate(buffer *buf) {
    /* Position it after packet_length and padding_length */
    const unsigned int offset = 5;
    if (buf->len < offset) {
        return;
    }
    buf_setpos(buf, offset);
    size_t max_size = buf->size - buf->pos;
    size_t new_size = LLVMFuzzerMutate(buf_getwriteptr(buf, max_size),
        buf->len - buf->pos, max_size);
    buf_setpos(buf, 0);
    buf_putint(buf, new_size);
    buf_setlen(buf, offset + new_size);
}


static const char* FIXED_VERSION = "SSH-2.0-dbfuzz\r\n";
static const size_t MAX_FUZZ_PACKETS = 500;
/* XXX This might need tuning */
static const size_t MAX_OUT_SIZE = 50000;

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
              size_t MaxSize, unsigned int Seed) {
    int i;
    unsigned short randstate[3] = {0,0,0};
    memcpy(randstate, &Seed, sizeof(Seed));

    /* 1% chance straight llvm mutate */
    if (nrand48(randstate) % 100 == 0) {
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }

    buffer inp_buf = {.data = Data, .size = Size, .len = Size, .pos = 0};
    buffer *inp = &inp_buf;

    /* Parse packets */
    buffer* packets[MAX_FUZZ_PACKETS] = {0};
    unsigned int num_packets = MAX_FUZZ_PACKETS;
    fuzz_get_packets(inp, packets, &num_packets);

    if (num_packets == 0) {
        // gotta do something
        memcpy(Data, FIXED_VERSION, MIN(strlen(FIXED_VERSION), MaxSize));
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }

    /* Start output */
    buffer *oup = buf_new(MAX_OUT_SIZE);
    /* Put a new banner to output */
    buf_putbytes(oup, FIXED_VERSION, strlen(FIXED_VERSION));

    /* Iterate output */
    for (i = 0; i < num_packets+1; i++) {
        // These are pointers to output
        buffer *out_packetA = NULL, *out_packetB = NULL;
        // These need to be freed
        buffer *alloc_packetA = NULL, *alloc_packetB = NULL;

        /* 5% chance each */
        const int optA = nrand48(randstate) % 20;
        const int other = nrand48(randstate) % num_packets;
        if (optA == 0) {
            /* Copy another */
            out_packetA = packets[nrand48(randstate) % num_packets];
        }
        if (optA == 1) {
            /* Mutate another */
            alloc_packetA = buf_new(RECV_MAX_PACKET_LEN);
            buffer *from = packets[nrand48(randstate) % num_packets];
            buf_putbytes(alloc_packetA, from->data, from->len);
            out_packetA = alloc_packetA;
            buf_llvm_mutate(out_packetA);
        }

        /* 10% chance each of mutate or drop */
        if (i < num_packets) {
            int optB = nrand48(randstate) % 10;
            if (optB == 0) {
                /* Copy as-is */
                out_packetB = packets[i];
            } 
            if (optB == 1) {
                /* Drop it */
            } 
            if (optB == 2) {
                /* Mutate it */
                alloc_packetB = buf_new(RECV_MAX_PACKET_LEN);
                buffer *from = packets[nrand48(randstate) % num_packets];
                buf_putbytes(alloc_packetB, from->data, from->len);
                out_packetB = alloc_packetB;
                buf_llvm_mutate(out_packetB);
            } 
        }

        if (out_packetA && oup->len + out_packetA->len <= oup->size) {
            buf_putbytes(oup, out_packetA->data, out_packetA->len);
        }
        if (out_packetB && oup->len + out_packetB->len <= oup->size) {
            buf_putbytes(oup, out_packetB->data, out_packetB->len);
        }
        if (alloc_packetA) {
            buf_free(alloc_packetA);
            alloc_packetA = NULL;
        }
        if (alloc_packetB) {
            buf_free(alloc_packetB);
            alloc_packetB = NULL;
        }
    }

    for (i = 0; i < num_packets; i++) {
        buf_free(packets[i]);
    }

    size_t ret_len = MIN(MaxSize, oup->len);
    memcpy(Data, oup->data, ret_len);
    buf_free(oup);
    return ret_len;
}

