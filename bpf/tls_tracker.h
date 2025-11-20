/*
    light weight TLS tracker.
*/

#ifndef __TLS_TRACKER_H__
#define __TLS_TRACKER_H__
#include "utils.h"

#define CONTENT_TYPE_CHANGE_CIPHER 0x14
#define CONTENT_TYPE_ALERT 0x15
#define CONTENT_TYPE_HANDSHAKE 0x16
#define CONTENT_TYPE_APP_DATA 0x17
#define HANDSHAKE_CLIENT_HELLO 0x01
#define HANDSHAKE_SERVER_HELLO 0x02

// https://www.rfc-editor.org/rfc/rfc5246
struct tls_record {
    u8 content_type; // handshake, alert, change cipher, app data
    u8 major;
    u8 minor;
    u16 length;
};

struct tls_handshake_header {
    u8 content_type; // client hello, server hello ...
    u8 len[3];
};

struct tls_handshake_version {
    u8 major;
    u8 minor;
};

// Extract TLS info
static inline void track_tls_version(struct __sk_buff *skb, pkt_info *pkt) {
    if (pkt->id->transport_protocol == IPPROTO_TCP) {
        void *data_end = (void *)(long)skb->data_end;
        struct tcphdr *tcp = (struct tcphdr *)pkt->l4_hdr;
        if (!tcp || ((void *)tcp + sizeof(*tcp) > data_end)) {
            return;
        }

        u8 len = tcp->doff * sizeof(u32);
        if (!len) {
            return;
        }

        struct tls_record rec;
        u32 offset = (long)pkt->l4_hdr - (long)skb->data + len;

        if ((bpf_skb_load_bytes(skb, offset, &rec, sizeof(rec))) < 0) {
            return;
        }
    TODO:
        faire en sorte
            d'ignorer la valeur de ssl_version selon les paquets; par exemple, osef dans client-hello, ce
                qui compte
                    c'est la version effective donnée par server-hello et utilisée par la suite En
                        fait,
            c'est surtout app-data qui compte(?) on peut ajouter pkt->tls_content_type qui permet de
                définir la façon d'aggreger
    
        Idées: on n'a aucune certitude que ce soit du TLS. Donc il faudrait changer d'approche, procéder par étapes:
        *. À chaque étape, on lit un peu plus loin et on check les valeurs possibles; si inconsistent, return "pas TLS"
        1. Lecture Record Header; Expect: type==14/15/16/17 ; version=3.0 (sslv3)/3.1(tls1.0 ou client-hello tls1.x)/3.2(tls1.1)/3.3(tls1.2 ou 1.3)
        2. Si Handshake, lecture handshake header; Expect: type==1/2/0b(certif)/0c/0e/10/ ; if something else we can assume it's an encrypted FINISH
        3. Si CLIENT_HELLO, lecture; Expect version=030[1-3]
            3a. Si version=030[1-2]; on retourne un bitfield disant qu'on a eu client hello deprecated
            3b. Si version=0303, lecture de la suite; on retourne un bitfield disant qu'on a eu client hello
        4. Si SERVER_HELLO, lecture; Expect version=030[1-3]
            4a. Si version=030[1-2]; on retourne un bitfield disant qu'on a eu server hello deprecated
            4b. Si version=0303, lecture de la suite; on retourne un bitfield disant qu'on a eu server hello + version + cipher
        5. Si Change Cipher: lecture, Expect version=030[1-3]
        6. Si AppData: lecture, Expect version=030[1-3]
        7. Si Alert: lecture, Expect version=030[1-3]
                
     
            /*

            1.2
	Handshake, ClientHello: header (4B) + Version (2B, 0303) + Random (32B) + Session (1B=len ??) + Ciphers (1B=len + N) + Compression (1B=len + N) + Extensions Len (2B) + Extensions (repeat: 2B=code, 2B=len, ...)

	Handshake, ServerHello: header (4B) + Version (2B, 0303) + Random (32B) + Session (1B=len ??) + Selected Cipher (2B) + Compression (1B) + Extensions Len (2B) + Extensions (repeat: 2B=code, 2B=len, ...)

1.3
	Handshake, ClientHello: header (4B) + Version (2B, 0303) + Random (32B) + Session (1B=len, always 0x20??) + Ciphers (1B=len + N) + Compression (2B=0x0100) + Extensions Len (2B) + Extensions (repeat: 2B=code, 2B=len, ...)

	Handshake, ServerHello: header (4B) + Version (2B, 0303) + Random (32B) + Session (1B=len, always 0x20??) + Selected Cipher (2B) + Compression (1B, always 0x00?) + Extensions Len (2B) + Extensions (repeat: 2B=code, 2B=len, ...)
		Extension - Supported Versions: code=0x002b, len=0x0002, content=0x0304 for 1.3



            */

    switch (rec.content_type) {
        case CONTENT_TYPE_HANDSHAKE: {
            pkt->ssl_version = ((u16)rec.major) << 8 | rec.minor;
            struct tls_handshake_header handshake;
            if (bpf_skb_load_bytes(skb, offset + sizeof(rec), &handshake, sizeof(handshake)) < 0) {
                return;
            }
            if (handshake.content_type == HANDSHAKE_CLIENT_HELLO ||
                handshake.content_type == HANDSHAKE_SERVER_HELLO) {
                struct tls_handshake_version handshake_version;
                if (bpf_skb_load_bytes(skb, offset + sizeof(rec) + sizeof(handshake),
                                       &handshake_version, sizeof(handshake_version)) < 0) {
                    return;
                }
                pkt->ssl_version = ((u16)handshake_version.major) << 8 | handshake_version.minor;
            }
            break;
        }
        case CONTENT_TYPE_CHANGE_CIPHER:
        case CONTENT_TYPE_ALERT:
        case CONTENT_TYPE_APP_DATA:
            pkt->ssl_version = ((u16)rec.major) << 8 | rec.minor;
            break;
        }
    }
}

#endif // __TLS_TRACKER_H__
