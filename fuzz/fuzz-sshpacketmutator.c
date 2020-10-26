#include "fuzz.h"
#include "dbutil.h"

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
            buf_incrpos(inp, newline - &inp->data[inp->pos]+1);
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
        //printf("at %d\n", inp->pos);
        //printhex("lenget", buf_getptr(inp, 48), 48);
        unsigned int packet_len = buf_getint(inp);
        // printf("len %u\n", packet_len);
        if (packet_len > RECV_MAX_PACKET_LEN-4) {
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
        // printf("incr pos %d to %d\n", packet_len, inp->pos);

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

    /* Avoid some allocations */
    /* XXX perhaps this complication isn't worthwhile */
    static buffer buf_oup, buf_alloc_packetA, buf_alloc_packetB;
    static buffer *oup = &buf_oup; 
    static buffer *alloc_packetA = &buf_alloc_packetA;
    static buffer *alloc_packetB = &buf_alloc_packetB;
    static int once = 1;
    if (once) {
        once = 0;
        // malloc doesn't get intercepted by epoch deallocator
        oup->size = MAX_OUT_SIZE;
        alloc_packetA->size = RECV_MAX_PACKET_LEN;
        alloc_packetB->size = RECV_MAX_PACKET_LEN;
        oup->data = malloc(oup->size);
        alloc_packetA->data = malloc(alloc_packetA->size);
        alloc_packetB->data = malloc(alloc_packetB->size);
    } 
    alloc_packetA->pos = 0;
    alloc_packetA->len = 0;
    alloc_packetB->pos = 0;
    alloc_packetB->len = 0;
    oup->pos = 0;
    oup->len = 0;

    unsigned int i;
    unsigned short randstate[3] = {0,0,0};
    memcpy(randstate, &Seed, sizeof(Seed));

    // printhex("mutator input", Data, Size);
    #if 0
    /* 1% chance straight llvm mutate */
    if (nrand48(randstate) % 100 == 0) {
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }
    #endif

    buffer inp_buf = {.data = Data, .size = Size, .len = Size, .pos = 0};
    buffer *inp = &inp_buf;

    /* Parse packets */
    buffer* packets[MAX_FUZZ_PACKETS];
    unsigned int num_packets = MAX_FUZZ_PACKETS;
    fuzz_get_packets(inp, packets, &num_packets);
    // printf("%d packets\n", num_packets);

    if (num_packets == 0) {
        // gotta do something
        memcpy(Data, FIXED_VERSION, MIN(strlen(FIXED_VERSION), MaxSize));
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }

    /* Start output */
    /* Put a new banner to output */
    buf_putbytes(oup, FIXED_VERSION, strlen(FIXED_VERSION));

    /* Iterate output */
    for (i = 0; i < num_packets+1; i++) {
        // These are pointers to output
        buffer *out_packetA = NULL, *out_packetB = NULL;
        alloc_packetA->pos = 0;
        alloc_packetA->len = 0;
        alloc_packetB->pos = 0;
        alloc_packetB->len = 0;

        /* 5% chance each */
        const int optA = nrand48(randstate) % 20;
        if (optA == 0) {
            /* Copy another */
            unsigned int other = nrand48(randstate) % num_packets;
            out_packetA = packets[other];
            // printf("%d copy another %d\n", i, other);
        }
        if (optA == 1) {
            /* Mutate another */
            unsigned int other = nrand48(randstate) % num_packets;
            buffer *from = packets[other];
            buf_putbytes(alloc_packetA, from->data, from->len);
            out_packetA = alloc_packetA;
            buf_llvm_mutate(out_packetA);
            // printf("%d mutate another %d\n", i, other);
        }

        if (i < num_packets) {
            int optB = nrand48(randstate) % 10;
            if (optB == 1) {
                /* 10% chance of drop */
                /* Drop it */
                // printf("%d drop\n", i);
            } else if (optB <= 6) {
                /* Mutate it, 50% chance */
                // printf("%d mutate\n", i);
                buffer *from = packets[nrand48(randstate) % num_packets];
                buf_putbytes(alloc_packetB, from->data, from->len);
                out_packetB = alloc_packetB;
                buf_llvm_mutate(out_packetB);
            } else {
                /* Copy as-is */
                out_packetB = packets[i];
                // printf("%d as-is\n", i);
            } 
        }

        if (out_packetA && oup->len + out_packetA->len <= oup->size) {
            buf_putbytes(oup, out_packetA->data, out_packetA->len);
        }
        if (out_packetB && oup->len + out_packetB->len <= oup->size) {
            buf_putbytes(oup, out_packetB->data, out_packetB->len);
        }
    }

    for (i = 0; i < num_packets; i++) {
        buf_free(packets[i]);
    }

    size_t ret_len = MIN(MaxSize, oup->len);
    memcpy(Data, oup->data, ret_len);
    // printhex("mutator done", Data, ret_len);
    return ret_len;
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *Data1, size_t Size1,
                                            const uint8_t *Data2, size_t Size2,
                                            uint8_t *Out, size_t MaxOutSize,
                                            unsigned int Seed) {
    unsigned short randstate[3] = {0,0,0};
    memcpy(randstate, &Seed, sizeof(Seed));

    unsigned int i;
    buffer inp_buf1 = {.data = (void*)Data1, .size = Size1, .len = Size1, .pos = 0};
    buffer *inp1 = &inp_buf1;
    buffer inp_buf2 = {.data = (void*)Data2, .size = Size2, .len = Size2, .pos = 0};
    buffer *inp2 = &inp_buf2;

    buffer* packets1[MAX_FUZZ_PACKETS];
    unsigned int num_packets1 = MAX_FUZZ_PACKETS;
    fuzz_get_packets(inp1, packets1, &num_packets1);
    buffer* packets2[MAX_FUZZ_PACKETS];
    unsigned int num_packets2 = MAX_FUZZ_PACKETS;
    fuzz_get_packets(inp2, packets2, &num_packets2);

    buffer *oup = buf_new(MAX_OUT_SIZE);
    /* Put a new banner to output */
    buf_putbytes(oup, FIXED_VERSION, strlen(FIXED_VERSION));

    for (i = 0; i < num_packets1+1; i++) {
        if (num_packets2 > 0 && nrand48(randstate) % 10 == 0) {
            /* 10% chance of taking another packet at each position */
            int other = nrand48(randstate) % num_packets2;
            buffer *otherp = packets2[other];
            if (oup->len + otherp->len <= oup->size) {
                buf_putbytes(oup, otherp->data, otherp->len);
            }
        }
        if (i < num_packets1) {
            buffer *thisp = packets1[i];
            if (oup->len + thisp->len <= oup->size) {
                buf_putbytes(oup, thisp->data, thisp->len);
            }
        }
    }

    for (i = 0; i < num_packets1; i++) {
        buf_free(packets1[i]);
    }
    for (i = 0; i < num_packets2; i++) {
        buf_free(packets2[i]);
    }

    size_t ret_len = MIN(MaxOutSize, oup->len);
    memcpy(Out, oup->data, ret_len);
    buf_free(oup);
    return ret_len;
}

