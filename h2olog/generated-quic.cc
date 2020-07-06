// Generated code. Do not edit it here!

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "quicly.h"

#include "h2olog.h"
#include "json.h"

#define STR_LEN 64
#define STR_LIT(s) s, strlen(s)

uint64_t seq = 0;

// BPF modules written in C
const char *bpf_text = R"__BPF__(

#include <linux/sched.h>

#define STR_LEN 64


typedef int64_t quicly_stream_id_t;

typedef enum {
    /**
     * initial state
     */
    QUICLY_SENDER_STATE_NONE,
    /**
     * to be sent. Changes to UNACKED when sent out by quicly_send
     */
    QUICLY_SENDER_STATE_SEND,
    /**
     * inflight. changes to SEND (when packet is deemed lost), or ACKED (when packet is ACKed)
     */
    QUICLY_SENDER_STATE_UNACKED,
    /**
     * the sent value acknowledged by remote peer
     */
    QUICLY_SENDER_STATE_ACKED,
} quicly_sender_state_t;


typedef struct st_quicly_address_token_plaintext_t quicly_address_token_plaintext_t;
typedef struct st_quicly_application_space_t quicly_application_space_t;
typedef struct st_quicly_cc_t quicly_cc_t;
typedef struct st_quicly_cid_encryptor_t quicly_cid_encryptor_t;
typedef struct st_quicly_cid_plaintext_t quicly_cid_plaintext_t;
typedef struct st_quicly_cid_t quicly_cid_t;
typedef struct st_quicly_cipher_context_t quicly_cipher_context_t;
typedef struct st_quicly_closed_by_remote_t quicly_closed_by_remote_t;
typedef struct st_quicly_conn_streamgroup_state_t quicly_conn_streamgroup_state_t;
typedef struct st_quicly_conn_t quicly_conn_t;
typedef struct st_quicly_context_t quicly_context_t;
typedef struct st_quicly_crypto_engine_t quicly_crypto_engine_t;
typedef struct st_quicly_default_scheduler_state_t quicly_default_scheduler_state_t;
typedef struct st_quicly_generate_resumption_token_t quicly_generate_resumption_token_t;
typedef struct st_quicly_handshake_space_t quicly_handshake_space_t;
typedef struct st_quicly_linklist_t quicly_linklist_t;
typedef struct st_quicly_local_cid_set_t quicly_local_cid_set_t;
typedef struct st_quicly_local_cid_t quicly_local_cid_t;
typedef struct st_quicly_max_stream_data_t quicly_max_stream_data_t;
typedef struct st_quicly_max_streams_t quicly_max_streams_t;
typedef struct st_quicly_maxsender_sent_t quicly_maxsender_sent_t;
typedef struct st_quicly_maxsender_t quicly_maxsender_t;
typedef struct st_quicly_now_t quicly_now_t;
typedef struct st_quicly_pending_path_challenge_t quicly_pending_path_challenge_t;
typedef struct st_quicly_pn_space_t quicly_pn_space_t;
typedef struct st_quicly_range_t quicly_range_t;
typedef struct st_quicly_ranges_t quicly_ranges_t;
typedef struct st_quicly_recvstate_t quicly_recvstate_t;
typedef struct st_quicly_remote_cid_set_t quicly_remote_cid_set_t;
typedef struct st_quicly_remote_cid_t quicly_remote_cid_t;
typedef struct st_quicly_retire_cid_set_t quicly_retire_cid_set_t;
typedef struct st_quicly_save_resumption_token_t quicly_save_resumption_token_t;
typedef struct st_quicly_send_context_t quicly_send_context_t;
typedef struct st_quicly_sendstate_sent_t quicly_sendstate_sent_t;
typedef struct st_quicly_sendstate_t quicly_sendstate_t;
typedef struct st_quicly_sent_block_t quicly_sent_block_t;
typedef struct st_quicly_sent_packet_t quicly_sent_packet_t;
typedef struct st_quicly_sent_t quicly_sent_t;
typedef struct st_quicly_sentmap_t quicly_sentmap_t;
typedef struct st_quicly_stream_callbacks_t quicly_stream_callbacks_t;
typedef struct st_quicly_stream_open_t quicly_stream_open_t;
typedef struct st_quicly_stream_scheduler_t quicly_stream_scheduler_t;
typedef struct st_quicly_stream_t quicly_stream_t;
typedef struct st_quicly_transport_parameters_t quicly_transport_parameters_t;

struct _st_quicly_conn_public_t {
	quicly_context_t *         ctx;
	quicly_state_t             state;
	struct {
		quicly_local_cid_set_t cid_set;
		quicly_address_t   address;
		quicly_cid_t       long_header_src_cid;
		struct st_quicly_conn_streamgroup_state_t bidi;
		struct st_quicly_conn_streamgroup_state_t uni;
	} local;
	struct {
		quicly_remote_cid_set_t cid_set;
		quicly_address_t   address;
		struct st_quicly_conn_streamgroup_state_t bidi;
		struct st_quicly_conn_streamgroup_state_t uni;
		quicly_transport_parameters_t transport_params;
		struct {
			unsigned int validated:1;
			unsigned int send_probe:1;
		} address_validation;
		uint64_t           largest_retire_prior_to;
	} remote;
	quicly_cid_t               original_dcid;
	struct st_quicly_default_scheduler_state_t _default_scheduler;
	struct {
		struct {
			uint64_t   received;
			uint64_t   decryption_failed;
			uint64_t   sent;
			uint64_t   lost;
			uint64_t   lost_time_threshold;
			uint64_t   ack_received;
			uint64_t   late_acked;
		} num_packets;
		struct {
			uint64_t   received;
			uint64_t   sent;
		} num_bytes;
		uint32_t           num_ptos;
	} stats;
	uint32_t                   version;
	void *                     data;
};
struct quicly_loss_conf_t {
	unsigned int               time_reordering_percentile;
	uint32_t                   min_pto;
	uint32_t                   default_initial_rtt;
	uint8_t                    num_speculative_ptos;
};
struct quicly_loss_t {
	const quicly_loss_conf_t  * conf;
	uint16_t *                 max_ack_delay;
	uint8_t *                  ack_delay_exponent;
	int8_t                     pto_count;
	int64_t                    time_of_last_packet_sent;
	uint64_t                   largest_acked_packet_plus1;
	uint64_t                   total_bytes_sent;
	int64_t                    loss_time;
	int64_t                    alarm_at;
	quicly_rtt_t               rtt;
};
struct quicly_rtt_t {
	uint32_t                   minimum;
	uint32_t                   smoothed;
	uint32_t                   variance;
	uint32_t                   latest;
};
union st_quicly_address_t {
	struct sockaddr    sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};
struct st_quicly_address_token_plaintext_t {
	enum {
		QUICLY_ADDRESS_TOKEN_TYPE_RETRY = 0,
		QUICLY_ADDRESS_TOKEN_TYPE_RESUMPTION = 1,
	} type;
	uint64_t                   issued_at;
	quicly_address_t           local;
	quicly_address_t           remote;
	union {
		struct {
			quicly_cid_t original_dcid;
			quicly_cid_t client_cid;
			quicly_cid_t server_cid;
		} retry;
		struct {
			uint8_t    bytes[256];
			size_t     len;
		} resumption;
	};
	struct {
		uint8_t            bytes[256];
		size_t             len;
	} appdata;
};
struct st_quicly_application_space_t {
	struct st_quicly_pn_space_t super;
	struct {
		struct {
			struct {
				ptls_cipher_context_t * zero_rtt;
				ptls_cipher_context_t * one_rtt;
			} header_protection;
			ptls_aead_context_t * aead[2];
			uint8_t    secret[64];
			struct {
				uint64_t prepared;
				uint64_t decrypted;
			} key_phase;
		} ingress;
		struct {
			struct st_quicly_cipher_context_t key;
			uint8_t    secret[64];
			uint64_t   key_phase;
			struct {
				uint64_t last;
				uint64_t next;
			} key_update_pn;
		} egress;
	} cipher;
	int                        one_rtt_writable;
};
struct st_quicly_cc_t {
	quicly_cc_type_t           type;
	uint32_t                   cwnd;
	uint32_t                   ssthresh;
	uint32_t                   stash;
	uint64_t                   recovery_end;
	uint32_t                   cwnd_initial;
	uint32_t                   cwnd_exiting_slow_start;
	uint32_t                   cwnd_minimum;
	uint32_t                   cwnd_maximum;
	uint32_t                   num_loss_episodes;
};
struct st_quicly_cid_encryptor_t {
	void                       (*encrypt_cid)(struct st_quicly_cid_encryptor_t *, quicly_cid_t *, void *, const quicly_cid_plaintext_t  *);
	size_t                     (*decrypt_cid)(struct st_quicly_cid_encryptor_t *, quicly_cid_plaintext_t *, const void  *, size_t);
	int                        (*generate_stateless_reset_token)(struct st_quicly_cid_encryptor_t *, void *, const void  *);
};
struct st_quicly_cid_plaintext_t {
	uint32_t                   master_id;
	uint32_t                   path_id:8;
	uint32_t                   thread_id:24;
	uint64_t                   node_id;
};
struct st_quicly_cid_t {
	uint8_t                    cid[20];
	uint8_t                    len;
};
struct st_quicly_cipher_context_t {
	ptls_aead_context_t *      aead;
	ptls_cipher_context_t *    header_protection;
};
struct st_quicly_closed_by_remote_t {
	void                       (*cb)(struct st_quicly_closed_by_remote_t *, quicly_conn_t *, int, uint64_t, const char  *, size_t);
};
struct st_quicly_conn_streamgroup_state_t {
	uint32_t                   num_streams;
	quicly_stream_id_t         next_stream_id;
};
struct st_quicly_conn_t {
	struct _st_quicly_conn_public_t super;
	struct st_quicly_handshake_space_t * initial;
	struct st_quicly_handshake_space_t * handshake;
	struct st_quicly_application_space_t * application;
	kh_quicly_stream_t_t *     streams;
	struct {
		struct {
			uint64_t   bytes_consumed;
			quicly_maxsender_t sender;
		} max_data;
		struct {
			quicly_maxsender_t uni;
			quicly_maxsender_t bidi;
		} max_streams;
		struct {
			uint64_t   next_sequence;
		} ack_frequency;
	} ingress;
	struct {
		quicly_sentmap_t   sentmap;
		uint64_t           max_lost_pn;
		quicly_loss_t      loss;
		uint64_t           packet_number;
		uint64_t           next_pn_to_skip;
		uint16_t           max_udp_payload_size;
		struct {
			uint16_t   error_code;
			uint64_t   frame_type;
			const char  * reason_phrase;
			long unsigned int num_packets_received;
			long unsigned int num_sent;
		} connection_close;
		struct {
			uint64_t   permitted;
			uint64_t   sent;
		} max_data;
		struct {
			struct st_quicly_max_streams_t uni;
			struct st_quicly_max_streams_t bidi;
		} max_streams;
		struct {
			struct st_quicly_pending_path_challenge_t * head;
			struct st_quicly_pending_path_challenge_t * * tail_ref;
		} path_challenge;
		struct {
			uint64_t   generation;
			uint64_t   max_acked;
			uint32_t   num_inflight;
		} new_token;
		struct {
			int64_t    update_at;
			uint64_t   sequence;
		} ack_frequency;
		int64_t            last_retransmittable_sent_at;
		int64_t            send_ack_at;
		quicly_cc_t        cc;
		struct {
			struct {
				quicly_linklist_t uni;
				quicly_linklist_t bidi;
			} blocked;
			quicly_linklist_t control;
		} pending_streams;
		uint8_t            pending_flows;
		quicly_retire_cid_set_t retire_cid;
	} egress;
	struct {
		ptls_t *           tls;
		ptls_handshake_properties_t handshake_properties;
		struct {
			ptls_raw_extension_t ext[2];
			ptls_buffer_t buf;
		} transport_params;
	} crypto;
	ptls_iovec_t               token;
	quicly_cid_t               retry_scid;
	struct {
		int64_t            at;
		uint8_t            should_rearm_on_send:1;
	} idle_timeout;
	struct {
		int64_t            now;
		uint8_t            lock_count;
		struct {
			struct {
				quicly_stream_id_t stream_id;
				quicly_sendstate_sent_t args;
			} active_acked_cache;
		} on_ack_stream;
	} stash;
};
struct st_quicly_context_t {
	ptls_context_t *           tls;
	uint16_t                   initial_egress_max_udp_payload_size;
	quicly_loss_conf_t         loss;
	quicly_transport_parameters_t transport_params;
	uint64_t                   max_packets_per_key;
	uint64_t                   max_crypto_bytes;
	unsigned int               enforce_version_negotiation:1;
	unsigned int               is_clustered:1;
	unsigned int               expand_client_hello:1;
	quicly_cid_encryptor_t *   cid_encryptor;
	quicly_stream_open_t *     stream_open;
	quicly_stream_scheduler_t * stream_scheduler;
	quicly_closed_by_remote_t * closed_by_remote;
	quicly_now_t *             now;
	quicly_save_resumption_token_t * save_resumption_token;
	quicly_generate_resumption_token_t * generate_resumption_token;
	quicly_crypto_engine_t *   crypto_engine;
};
struct st_quicly_crypto_engine_t {
	int                        (*setup_cipher)(struct st_quicly_crypto_engine_t *, quicly_conn_t *, size_t, int, ptls_cipher_context_t * *, ptls_aead_context_t * *, ptls_aead_algorithm_t *, ptls_hash_algorithm_t *, const void  *);
	void                       (*encrypt_packet)(struct st_quicly_crypto_engine_t *, quicly_conn_t *, ptls_cipher_context_t *, ptls_aead_context_t *, ptls_iovec_t, size_t, size_t, uint64_t, int);
};
struct st_quicly_default_scheduler_state_t {
	quicly_linklist_t          active;
	quicly_linklist_t          blocked;
};
struct st_quicly_generate_resumption_token_t {
	int                        (*cb)(struct st_quicly_generate_resumption_token_t *, quicly_conn_t *, ptls_buffer_t *, quicly_address_token_plaintext_t *);
};
struct st_quicly_handshake_space_t {
	struct st_quicly_pn_space_t super;
	struct {
		struct st_quicly_cipher_context_t ingress;
		struct st_quicly_cipher_context_t egress;
	} cipher;
	uint16_t                   largest_ingress_udp_payload_size;
};
struct st_quicly_linklist_t {
	struct st_quicly_linklist_t * prev;
	struct st_quicly_linklist_t * next;
};
struct st_quicly_local_cid_set_t {
	quicly_cid_plaintext_t     plaintext;
	quicly_local_cid_t         cids[4];
	size_t                     _size;
	quicly_cid_encryptor_t *   _encryptor;
};
struct st_quicly_local_cid_t {
	enum en_quicly_local_cid_state_t state;
	uint64_t                   sequence;
	quicly_cid_t               cid;
	uint8_t                    stateless_reset_token[16];
};
struct st_quicly_max_stream_data_t {
	uint64_t                   bidi_local;
	uint64_t                   bidi_remote;
	uint64_t                   uni;
};
struct st_quicly_max_streams_t {
	uint64_t                   count;
	quicly_maxsender_t         blocked_sender;
};
struct st_quicly_maxsender_sent_t {
	uint64_t                   inflight:1;
	uint64_t                   value:63;
};
struct st_quicly_maxsender_t {
	int64_t                    max_committed;
	int64_t                    max_acked;
	size_t                     num_inflight;
	unsigned int               force_send:1;
};
struct st_quicly_now_t {
	int64_t                    (*cb)(struct st_quicly_now_t *);
};
struct st_quicly_pending_path_challenge_t {
	struct st_quicly_pending_path_challenge_t * next;
	uint8_t                    is_response;
	uint8_t                    data[8];
};
struct st_quicly_pn_space_t {
	quicly_ranges_t            ack_queue;
	int64_t                    largest_pn_received_at;
	uint64_t                   next_expected_packet_number;
	uint32_t                   unacked_count;
	uint32_t                   packet_tolerance;
	uint8_t                    ignore_order;
};
struct st_quicly_range_t {
	uint64_t                   start;
	uint64_t                   end;
};
struct st_quicly_ranges_t {
	quicly_range_t *           ranges;
	size_t                     num_ranges;
	size_t                     capacity;
	quicly_range_t             _initial;
};
struct st_quicly_recvstate_t {
	quicly_ranges_t            received;
	uint64_t                   data_off;
	uint64_t                   eos;
};
struct st_quicly_remote_cid_set_t {
	quicly_remote_cid_t        cids[4];
	uint64_t                   _largest_sequence_expected;
};
struct st_quicly_remote_cid_t {
	int                        is_active;
	uint64_t                   sequence;
	struct st_quicly_cid_t cid;
	uint8_t                    stateless_reset_token[16];
};
struct st_quicly_retire_cid_set_t {
	uint64_t                   sequences[8];
	size_t                     _num_pending;
};
struct st_quicly_save_resumption_token_t {
	int                        (*cb)(struct st_quicly_save_resumption_token_t *, quicly_conn_t *, ptls_iovec_t);
};
struct st_quicly_send_context_t {
	struct {
		struct st_quicly_cipher_context_t * cipher;
		uint8_t            first_byte;
	} current;
	struct {
		struct st_quicly_cipher_context_t * cipher;
		uint8_t *          first_byte_at;
		uint8_t            ack_eliciting:1;
	} target;
	struct iovec *             datagrams;
	size_t                     max_datagrams;
	size_t                     num_datagrams;
	struct {
		uint8_t *          datagram;
		uint8_t *          end;
	} payload_buf;
	ssize_t                    send_window;
	uint8_t *                  dst;
	uint8_t *                  dst_end;
	uint8_t *                  dst_payload_from;
};
struct st_quicly_sendstate_sent_t {
	uint64_t                   start;
	uint64_t                   end;
};
struct st_quicly_sendstate_t {
	quicly_ranges_t            acked;
	quicly_ranges_t            pending;
	uint64_t                   size_inflight;
	uint64_t                   final_size;
};
struct st_quicly_sent_block_t {
	struct st_quicly_sent_block_t * next;
	size_t                     num_entries;
	size_t                     next_insert_at;
	quicly_sent_t              entries[16];
};
struct st_quicly_sent_packet_t {
	uint64_t                   packet_number;
	int64_t                    sent_at;
	uint8_t                    ack_epoch;
	uint8_t                    ack_eliciting:1;
	uint8_t                    frames_in_flight:1;
	uint16_t                   cc_bytes_in_flight;
};
struct st_quicly_sent_t {
	quicly_sent_acked_cb       acked;
	union {
		quicly_sent_packet_t packet;
		struct {
			quicly_range_t range;
		} ack;
		struct {
			quicly_stream_id_t stream_id;
			quicly_sendstate_sent_t args;
		} stream;
		struct {
			quicly_stream_id_t stream_id;
			quicly_maxsender_sent_t args;
		} max_stream_data;
		struct {
			quicly_maxsender_sent_t args;
		} max_data;
		struct {
			int        uni;
			quicly_maxsender_sent_t args;
		} max_streams;
		struct {
			int        uni;
			quicly_maxsender_sent_t args;
		} streams_blocked;
		struct {
			quicly_stream_id_t stream_id;
		} stream_state_sender;
		struct {
			int        is_inflight;
			uint64_t   generation;
		} new_token;
		struct {
			uint64_t   sequence;
		} new_connection_id;
		struct {
			uint64_t   sequence;
		} retire_connection_id;
	} data;
};
struct st_quicly_sentmap_t {
	struct st_quicly_sent_block_t * head;
	struct st_quicly_sent_block_t * tail;
	size_t                     num_packets;
	size_t                     bytes_in_flight;
	quicly_sent_t *            _pending_packet;
};
struct st_quicly_stream_callbacks_t {
	void                       (*on_destroy)(quicly_stream_t *, int);
	void                       (*on_send_shift)(quicly_stream_t *, size_t);
	void                       (*on_send_emit)(quicly_stream_t *, size_t, void *, size_t *, int *);
	void                       (*on_send_stop)(quicly_stream_t *, int);
	void                       (*on_receive)(quicly_stream_t *, size_t, const void  *, size_t);
	void                       (*on_receive_reset)(quicly_stream_t *, int);
};
struct st_quicly_stream_open_t {
	int                        (*cb)(struct st_quicly_stream_open_t *, quicly_stream_t *);
};
struct st_quicly_stream_scheduler_t {
	int                        (*can_send)(struct st_quicly_stream_scheduler_t *, quicly_conn_t *, int);
	int                        (*do_send)(struct st_quicly_stream_scheduler_t *, quicly_conn_t *, quicly_send_context_t *);
	int                        (*update_state)(struct st_quicly_stream_scheduler_t *, quicly_stream_t *);
};
struct st_quicly_stream_t {
	quicly_conn_t *            conn;
	quicly_stream_id_t         stream_id;
	const quicly_stream_callbacks_t  * callbacks;
	quicly_sendstate_t         sendstate;
	quicly_recvstate_t         recvstate;
	void *                     data;
	unsigned int               streams_blocked:1;
	struct {
		uint64_t           max_stream_data;
		struct {
			quicly_sender_state_t sender_state;
			uint16_t   error_code;
		} stop_sending;
		struct {
			quicly_sender_state_t sender_state;
			uint16_t   error_code;
		} reset_stream;
		quicly_maxsender_t max_stream_data_sender;
		struct {
			quicly_linklist_t control;
			quicly_linklist_t default_scheduler;
		} pending_link;
	} _send_aux;
	struct {
		uint32_t           window;
		uint32_t           max_ranges;
	} _recv_aux;
};
struct st_quicly_transport_parameters_t {
	quicly_max_stream_data_t   max_stream_data;
	uint64_t                   max_data;
	uint64_t                   max_idle_timeout;
	uint64_t                   max_streams_bidi;
	uint64_t                   max_streams_uni;
	uint64_t                   max_udp_payload_size;
	uint8_t                    ack_delay_exponent;
	uint16_t                   max_ack_delay;
	uint64_t                   min_ack_delay_usec;
	uint8_t                    disable_active_migration:1;
	uint64_t                   active_connection_id_limit;
};



struct quic_event_t {
  uint8_t id;

  union {
    struct { // quicly:connect
      uint32_t master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
    } accept;
    struct { // quicly:free
      uint32_t master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      uint32_t master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[1];
      size_t bytes_len;
    } receive;
    struct { // quicly:version_switch
      uint32_t master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      uint32_t master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      uint32_t master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_decrypt
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t decrypted_len;
    } crypto_decrypt;
    struct { // quicly:crypto_handshake
      uint32_t master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      uint32_t master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      uint32_t master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_prepare
      uint32_t master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_commit
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      int ack_only;
    } packet_commit;
    struct { // quicly:packet_acked
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      int is_late_ack;
    } packet_acked;
    struct { // quicly:packet_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } packet_lost;
    struct { // quicly:pto
      uint32_t master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      uint32_t master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      uint32_t master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:ack_send
      uint32_t master_id;
      int64_t at;
      uint64_t largest_acked;
      uint64_t ack_delay;
    } ack_send;
    struct { // quicly:ping_send
      uint32_t master_id;
      int64_t at;
    } ping_send;
    struct { // quicly:ping_receive
      uint32_t master_id;
      int64_t at;
    } ping_receive;
    struct { // quicly:transport_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:max_data_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_send;
    struct { // quicly:max_data_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_receive;
    struct { // quicly:max_streams_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t limit;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      uint32_t master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      uint32_t master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      uint32_t master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:new_connection_id_send
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_send;
    struct { // quicly:new_connection_id_receive
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_receive;
    struct { // quicly:retire_connection_id_send
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_send;
    struct { // quicly:retire_connection_id_receive
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_receive;
    struct { // quicly:data_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_receive;
    struct { // quicly:ack_frequency_receive
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t packet_tolerance;
      uint64_t max_ack_delay;
      int ignore_order;
    } ack_frequency_receive;
    struct { // quicly:quictrace_sent
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
    } quictrace_sent;
    struct { // quicly:quictrace_recv
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_recv;
    struct { // quicly:quictrace_send_stream
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_recv_ack
      uint32_t master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } quictrace_recv_ack;
    struct { // quicly:quictrace_recv_ack_delay
      uint32_t master_id;
      int64_t at;
      int64_t ack_delay;
    } quictrace_recv_ack_delay;
    struct { // quicly:quictrace_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_lost;
    struct { // quicly:quictrace_cc_ack
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // quicly:conn_stats
      uint32_t master_id;
      int64_t at;
      size_t size;
    } conn_stats;
    struct { // h2o:h3_accept
      uint64_t conn_id;
      uint32_t master_id;
    } h3_accept;
    struct { // h2o:h3_close
      uint64_t conn_id;
      uint32_t master_id;
    } h3_close;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
      uint32_t master_id;
    } send_response_header;

    };
  };
  
BPF_PERF_OUTPUT(events);

// HTTP/3 tracing
BPF_HASH(h2o_to_quicly_conn, u64, u32);

// tracepoint sched:sched_process_exit
int trace_sched_process_exit(struct tracepoint__sched__sched_process_exit *ctx) {
  const struct task_struct *task = (const struct task_struct*)bpf_get_current_task();
  pid_t h2o_pid = task->tgid;
  pid_t h2o_tid = task->pid;
  if (!(h2o_pid == H2OLOG_H2O_PID && h2o_tid == H2OLOG_H2O_PID)) {
    return 0;
  }
  struct quic_event_t ev = { .id = 1 };
  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}

// quicly:connect
int trace_quicly__connect(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 2 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.connect.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.connect.at);
  // uint32_t version
  bpf_usdt_readarg(3, ctx, &event.connect.version);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:accept
int trace_quicly__accept(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 3 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.accept.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.accept.at);
  // const char * dcid
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.accept.dcid, sizeof(event.accept.dcid), buf);
  // struct st_quicly_address_token_plaintext_t * address_token
  struct st_quicly_address_token_plaintext_t  address_token = {};
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&address_token, sizeof(address_token), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:free
int trace_quicly__free(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 4 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.free.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.free.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:send
int trace_quicly__send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 5 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.send.at);
  // int state
  bpf_usdt_readarg(3, ctx, &event.send.state);
  // const char * dcid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.send.dcid, sizeof(event.send.dcid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:receive
int trace_quicly__receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 6 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.receive.at);
  // const char * dcid
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.receive.dcid, sizeof(event.receive.dcid), buf);
  // const void * bytes
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.receive.bytes, sizeof(event.receive.bytes), buf);
  // size_t bytes_len
  bpf_usdt_readarg(5, ctx, &event.receive.bytes_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:version_switch
int trace_quicly__version_switch(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 7 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.version_switch.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.version_switch.at);
  // uint32_t new_version
  bpf_usdt_readarg(3, ctx, &event.version_switch.new_version);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:idle_timeout
int trace_quicly__idle_timeout(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 8 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.idle_timeout.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.idle_timeout.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stateless_reset_receive
int trace_quicly__stateless_reset_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 9 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stateless_reset_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stateless_reset_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_decrypt
int trace_quicly__crypto_decrypt(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 10 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_decrypt.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_decrypt.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.crypto_decrypt.pn);
  // const void * decrypted (ignored)
  // size_t decrypted_len
  bpf_usdt_readarg(5, ctx, &event.crypto_decrypt.decrypted_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_handshake
int trace_quicly__crypto_handshake(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 11 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_handshake.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_handshake.at);
  // int ret
  bpf_usdt_readarg(3, ctx, &event.crypto_handshake.ret);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_update_secret
int trace_quicly__crypto_update_secret(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 12 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_update_secret.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_update_secret.at);
  // int is_enc
  bpf_usdt_readarg(3, ctx, &event.crypto_update_secret.is_enc);
  // uint8_t epoch
  bpf_usdt_readarg(4, ctx, &event.crypto_update_secret.epoch);
  // const char * label
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.crypto_update_secret.label, sizeof(event.crypto_update_secret.label), buf);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_send_key_update
int trace_quicly__crypto_send_key_update(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 13 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_send_key_update.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_send_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_send_key_update.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_send_key_update_confirmed
int trace_quicly__crypto_send_key_update_confirmed(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 14 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_send_key_update_confirmed.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_send_key_update_confirmed.at);
  // uint64_t next_pn
  bpf_usdt_readarg(3, ctx, &event.crypto_send_key_update_confirmed.next_pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_receive_key_update
int trace_quicly__crypto_receive_key_update(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 15 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_receive_key_update.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:crypto_receive_key_update_prepare
int trace_quicly__crypto_receive_key_update_prepare(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 16 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.crypto_receive_key_update_prepare.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.crypto_receive_key_update_prepare.at);
  // uint64_t phase
  bpf_usdt_readarg(3, ctx, &event.crypto_receive_key_update_prepare.phase);
  // const char * secret (ignored)

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_prepare
int trace_quicly__packet_prepare(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 17 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_prepare.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_prepare.at);
  // uint8_t first_octet
  bpf_usdt_readarg(3, ctx, &event.packet_prepare.first_octet);
  // const char * dcid
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.packet_prepare.dcid, sizeof(event.packet_prepare.dcid), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_commit
int trace_quicly__packet_commit(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 18 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_commit.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_commit.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_commit.pn);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.packet_commit.len);
  // int ack_only
  bpf_usdt_readarg(5, ctx, &event.packet_commit.ack_only);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_acked
int trace_quicly__packet_acked(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 19 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_acked.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_acked.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_acked.pn);
  // int is_late_ack
  bpf_usdt_readarg(4, ctx, &event.packet_acked.is_late_ack);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:packet_lost
int trace_quicly__packet_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 20 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.packet_lost.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.packet_lost.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.packet_lost.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:pto
int trace_quicly__pto(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 21 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.pto.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.pto.at);
  // size_t inflight
  bpf_usdt_readarg(3, ctx, &event.pto.inflight);
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.pto.cwnd);
  // int8_t pto_count
  bpf_usdt_readarg(5, ctx, &event.pto.pto_count);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:cc_ack_received
int trace_quicly__cc_ack_received(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 22 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.cc_ack_received.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.cc_ack_received.at);
  // uint64_t largest_acked
  bpf_usdt_readarg(3, ctx, &event.cc_ack_received.largest_acked);
  // size_t bytes_acked
  bpf_usdt_readarg(4, ctx, &event.cc_ack_received.bytes_acked);
  // uint32_t cwnd
  bpf_usdt_readarg(5, ctx, &event.cc_ack_received.cwnd);
  // size_t inflight
  bpf_usdt_readarg(6, ctx, &event.cc_ack_received.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:cc_congestion
int trace_quicly__cc_congestion(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 23 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.cc_congestion.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.cc_congestion.at);
  // uint64_t max_lost_pn
  bpf_usdt_readarg(3, ctx, &event.cc_congestion.max_lost_pn);
  // size_t inflight
  bpf_usdt_readarg(4, ctx, &event.cc_congestion.inflight);
  // uint32_t cwnd
  bpf_usdt_readarg(5, ctx, &event.cc_congestion.cwnd);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:ack_send
int trace_quicly__ack_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 24 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.ack_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ack_send.at);
  // uint64_t largest_acked
  bpf_usdt_readarg(3, ctx, &event.ack_send.largest_acked);
  // uint64_t ack_delay
  bpf_usdt_readarg(4, ctx, &event.ack_send.ack_delay);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:ping_send
int trace_quicly__ping_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 25 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.ping_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ping_send.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:ping_receive
int trace_quicly__ping_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 26 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.ping_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ping_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:transport_close_send
int trace_quicly__transport_close_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 27 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.transport_close_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.transport_close_send.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.transport_close_send.error_code);
  // uint64_t frame_type
  bpf_usdt_readarg(4, ctx, &event.transport_close_send.frame_type);
  // const char * reason_phrase
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.transport_close_send.reason_phrase, sizeof(event.transport_close_send.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:transport_close_receive
int trace_quicly__transport_close_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 28 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.transport_close_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.transport_close_receive.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.transport_close_receive.error_code);
  // uint64_t frame_type
  bpf_usdt_readarg(4, ctx, &event.transport_close_receive.frame_type);
  // const char * reason_phrase
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.transport_close_receive.reason_phrase, sizeof(event.transport_close_receive.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:application_close_send
int trace_quicly__application_close_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 29 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.application_close_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.application_close_send.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.application_close_send.error_code);
  // const char * reason_phrase
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.application_close_send.reason_phrase, sizeof(event.application_close_send.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:application_close_receive
int trace_quicly__application_close_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 30 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.application_close_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.application_close_receive.at);
  // uint64_t error_code
  bpf_usdt_readarg(3, ctx, &event.application_close_receive.error_code);
  // const char * reason_phrase
  bpf_usdt_readarg(4, ctx, &buf);
  bpf_probe_read(&event.application_close_receive.reason_phrase, sizeof(event.application_close_receive.reason_phrase), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_send
int trace_quicly__stream_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 31 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_send.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.stream_send.stream_id = stream.stream_id; /* quicly_stream_id_t */
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_send.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_send.len);
  // int is_fin
  bpf_usdt_readarg(6, ctx, &event.stream_send.is_fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_receive
int trace_quicly__stream_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 32 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_receive.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.stream_receive.stream_id = stream.stream_id; /* quicly_stream_id_t */
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_receive.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_receive.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_acked
int trace_quicly__stream_acked(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 33 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_acked.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_acked.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_acked.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_acked.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_acked.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_lost
int trace_quicly__stream_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 34 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_lost.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_lost.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_lost.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.stream_lost.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.stream_lost.len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_data_send
int trace_quicly__max_data_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 35 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_data_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_data_send.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_data_receive
int trace_quicly__max_data_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 36 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_data_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_data_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_data_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_streams_send
int trace_quicly__max_streams_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 37 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_streams_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_streams_send.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_streams_receive
int trace_quicly__max_streams_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 38 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_streams_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_streams_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.max_streams_receive.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.max_streams_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_stream_data_send
int trace_quicly__max_stream_data_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 39 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_stream_data_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_send.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.max_stream_data_send.stream_id = stream.stream_id; /* quicly_stream_id_t */
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_send.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:max_stream_data_receive
int trace_quicly__max_stream_data_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 40 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.max_stream_data_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.max_stream_data_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.max_stream_data_receive.stream_id);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.max_stream_data_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_token_send
int trace_quicly__new_token_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 41 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_token_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_send.at);
  // uint8_t * token
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.new_token_send.token, sizeof(event.new_token_send.token), buf);
  // size_t token_len
  bpf_usdt_readarg(4, ctx, &event.new_token_send.token_len);
  // uint64_t generation
  bpf_usdt_readarg(5, ctx, &event.new_token_send.generation);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_token_acked
int trace_quicly__new_token_acked(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 42 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_token_acked.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_acked.at);
  // uint64_t generation
  bpf_usdt_readarg(3, ctx, &event.new_token_acked.generation);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_token_receive
int trace_quicly__new_token_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 43 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_token_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_token_receive.at);
  // uint8_t * token
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.new_token_receive.token, sizeof(event.new_token_receive.token), buf);
  // size_t token_len
  bpf_usdt_readarg(4, ctx, &event.new_token_receive.token_len);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:handshake_done_send
int trace_quicly__handshake_done_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 44 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.handshake_done_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_send.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:handshake_done_receive
int trace_quicly__handshake_done_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 45 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.handshake_done_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.handshake_done_receive.at);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:streams_blocked_send
int trace_quicly__streams_blocked_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 46 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.streams_blocked_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_send.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_send.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_send.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:streams_blocked_receive
int trace_quicly__streams_blocked_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 47 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.streams_blocked_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.streams_blocked_receive.at);
  // uint64_t limit
  bpf_usdt_readarg(3, ctx, &event.streams_blocked_receive.limit);
  // int is_unidirectional
  bpf_usdt_readarg(4, ctx, &event.streams_blocked_receive.is_unidirectional);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_connection_id_send
int trace_quicly__new_connection_id_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 48 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_connection_id_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_connection_id_send.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.new_connection_id_send.sequence);
  // uint64_t retire_prior_to
  bpf_usdt_readarg(4, ctx, &event.new_connection_id_send.retire_prior_to);
  // const char * cid
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_send.cid, sizeof(event.new_connection_id_send.cid), buf);
  // const char * stateless_reset_token
  bpf_usdt_readarg(6, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_send.stateless_reset_token, sizeof(event.new_connection_id_send.stateless_reset_token), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:new_connection_id_receive
int trace_quicly__new_connection_id_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 49 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.new_connection_id_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.new_connection_id_receive.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.new_connection_id_receive.sequence);
  // uint64_t retire_prior_to
  bpf_usdt_readarg(4, ctx, &event.new_connection_id_receive.retire_prior_to);
  // const char * cid
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_receive.cid, sizeof(event.new_connection_id_receive.cid), buf);
  // const char * stateless_reset_token
  bpf_usdt_readarg(6, ctx, &buf);
  bpf_probe_read(&event.new_connection_id_receive.stateless_reset_token, sizeof(event.new_connection_id_receive.stateless_reset_token), buf);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:retire_connection_id_send
int trace_quicly__retire_connection_id_send(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 50 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.retire_connection_id_send.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.retire_connection_id_send.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.retire_connection_id_send.sequence);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:retire_connection_id_receive
int trace_quicly__retire_connection_id_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 51 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.retire_connection_id_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.retire_connection_id_receive.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.retire_connection_id_receive.sequence);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:data_blocked_receive
int trace_quicly__data_blocked_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 52 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.data_blocked_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.data_blocked_receive.at);
  // uint64_t off
  bpf_usdt_readarg(3, ctx, &event.data_blocked_receive.off);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:stream_data_blocked_receive
int trace_quicly__stream_data_blocked_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 53 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.stream_data_blocked_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.stream_data_blocked_receive.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.stream_data_blocked_receive.stream_id);
  // uint64_t limit
  bpf_usdt_readarg(4, ctx, &event.stream_data_blocked_receive.limit);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:ack_frequency_receive
int trace_quicly__ack_frequency_receive(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 54 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.ack_frequency_receive.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.ack_frequency_receive.at);
  // uint64_t sequence
  bpf_usdt_readarg(3, ctx, &event.ack_frequency_receive.sequence);
  // uint64_t packet_tolerance
  bpf_usdt_readarg(4, ctx, &event.ack_frequency_receive.packet_tolerance);
  // uint64_t max_ack_delay
  bpf_usdt_readarg(5, ctx, &event.ack_frequency_receive.max_ack_delay);
  // int ignore_order
  bpf_usdt_readarg(6, ctx, &event.ack_frequency_receive.ignore_order);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_sent
int trace_quicly__quictrace_sent(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 55 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_sent.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_sent.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_sent.pn);
  // size_t len
  bpf_usdt_readarg(4, ctx, &event.quictrace_sent.len);
  // uint8_t packet_type
  bpf_usdt_readarg(5, ctx, &event.quictrace_sent.packet_type);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv
int trace_quicly__quictrace_recv(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 56 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_send_stream
int trace_quicly__quictrace_send_stream(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 57 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_send_stream.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_send_stream.at);
  // struct st_quicly_stream_t * stream
  struct st_quicly_stream_t  stream = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stream, sizeof(stream), buf);
  event.quictrace_send_stream.stream_id = stream.stream_id; /* quicly_stream_id_t */
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.quictrace_send_stream.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.quictrace_send_stream.len);
  // int fin
  bpf_usdt_readarg(6, ctx, &event.quictrace_send_stream.fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv_stream
int trace_quicly__quictrace_recv_stream(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 58 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv_stream.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_stream.at);
  // int64_t stream_id
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_stream.stream_id);
  // uint64_t off
  bpf_usdt_readarg(4, ctx, &event.quictrace_recv_stream.off);
  // size_t len
  bpf_usdt_readarg(5, ctx, &event.quictrace_recv_stream.len);
  // int fin
  bpf_usdt_readarg(6, ctx, &event.quictrace_recv_stream.fin);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv_ack
int trace_quicly__quictrace_recv_ack(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 59 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv_ack.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_ack.at);
  // uint64_t ack_block_begin
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_ack.ack_block_begin);
  // uint64_t ack_block_end
  bpf_usdt_readarg(4, ctx, &event.quictrace_recv_ack.ack_block_end);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_recv_ack_delay
int trace_quicly__quictrace_recv_ack_delay(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 60 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_recv_ack_delay.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_recv_ack_delay.at);
  // int64_t ack_delay
  bpf_usdt_readarg(3, ctx, &event.quictrace_recv_ack_delay.ack_delay);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_lost
int trace_quicly__quictrace_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 61 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_lost.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_lost.at);
  // uint64_t pn
  bpf_usdt_readarg(3, ctx, &event.quictrace_lost.pn);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_cc_ack
int trace_quicly__quictrace_cc_ack(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 62 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_cc_ack.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_ack.at);
  // struct quicly_rtt_t * rtt
  struct quicly_rtt_t  rtt = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof(rtt), buf);
  event.quictrace_cc_ack.minimum = rtt.minimum; /* uint32_t */
  event.quictrace_cc_ack.smoothed = rtt.smoothed; /* uint32_t */
  event.quictrace_cc_ack.variance = rtt.variance; /* uint32_t */
  event.quictrace_cc_ack.latest = rtt.latest; /* uint32_t */
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.quictrace_cc_ack.cwnd);
  // size_t inflight
  bpf_usdt_readarg(5, ctx, &event.quictrace_cc_ack.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:quictrace_cc_lost
int trace_quicly__quictrace_cc_lost(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 63 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.quictrace_cc_lost.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.quictrace_cc_lost.at);
  // struct quicly_rtt_t * rtt
  struct quicly_rtt_t  rtt = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&rtt, sizeof(rtt), buf);
  event.quictrace_cc_lost.minimum = rtt.minimum; /* uint32_t */
  event.quictrace_cc_lost.smoothed = rtt.smoothed; /* uint32_t */
  event.quictrace_cc_lost.variance = rtt.variance; /* uint32_t */
  event.quictrace_cc_lost.latest = rtt.latest; /* uint32_t */
  // uint32_t cwnd
  bpf_usdt_readarg(4, ctx, &event.quictrace_cc_lost.cwnd);
  // size_t inflight
  bpf_usdt_readarg(5, ctx, &event.quictrace_cc_lost.inflight);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// quicly:conn_stats
int trace_quicly__conn_stats(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 65 };

  // struct st_quicly_conn_t * conn
  struct st_quicly_conn_t  conn = {};
  bpf_usdt_readarg(1, ctx, &buf);
  bpf_probe_read(&conn, sizeof(conn), buf);
  event.conn_stats.master_id = conn.local.cid_set.plaintext.master_id; /* uint32_t */
  // int64_t at
  bpf_usdt_readarg(2, ctx, &event.conn_stats.at);
  // struct st_quicly_stats_t * stats
  struct st_quicly_stats_t  stats = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&stats, sizeof(stats), buf);
  // size_t size
  bpf_usdt_readarg(4, ctx, &event.conn_stats.size);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// h2o:h3_accept
int trace_h2o__h3_accept(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 69 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3_accept.conn_id);
  // struct st_h2o_conn_t * conn (ignored)
  // struct st_quicly_conn_t * quic
  struct st_quicly_conn_t  quic = {};
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&quic, sizeof(quic), buf);
  event.h3_accept.master_id = quic.local.cid_set.plaintext.master_id; /* uint32_t */

  h2o_to_quicly_conn.update(&event.h3_accept.conn_id, &event.h3_accept.master_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// h2o:h3_close
int trace_h2o__h3_close(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 70 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.h3_close.conn_id);

  const uint32_t *master_conn_id_ptr = h2o_to_quicly_conn.lookup(&event.h3_close.conn_id);
  if (master_conn_id_ptr != NULL) {
    event.h3_close.master_id = *master_conn_id_ptr;
  } else {
    bpf_trace_printk("h2o's conn_id=%lu is not associated to master_conn_id\n", event.h3_close.conn_id);
  }
  h2o_to_quicly_conn.delete(&event.h3_close.conn_id);

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}
// h2o:send_response_header
int trace_h2o__send_response_header(struct pt_regs *ctx) {
  void *buf = NULL;
  struct quic_event_t event = { .id = 79 };

  // uint64_t conn_id
  bpf_usdt_readarg(1, ctx, &event.send_response_header.conn_id);
  // uint64_t req_id
  bpf_usdt_readarg(2, ctx, &event.send_response_header.req_id);
  // const char * name
  bpf_usdt_readarg(3, ctx, &buf);
  bpf_probe_read(&event.send_response_header.name, sizeof(event.send_response_header.name), buf);
  // size_t name_len
  bpf_usdt_readarg(4, ctx, &event.send_response_header.name_len);
  // const char * value
  bpf_usdt_readarg(5, ctx, &buf);
  bpf_probe_read(&event.send_response_header.value, sizeof(event.send_response_header.value), buf);
  // size_t value_len
  bpf_usdt_readarg(6, ctx, &event.send_response_header.value_len);

  const uint32_t *master_conn_id_ptr = h2o_to_quicly_conn.lookup(&event.send_response_header.conn_id);
  if (master_conn_id_ptr == NULL)
    return 0;
  event.send_response_header.master_id = *master_conn_id_ptr;

#ifdef CHECK_ALLOWED_RES_HEADER_NAME
  if (!CHECK_ALLOWED_RES_HEADER_NAME(event.send_response_header.name, event.send_response_header.name_len))
    return 0;
#endif

  if (events.perf_submit(ctx, &event, sizeof(event)) != 0)
    bpf_trace_printk("failed to perf_submit\n");

  return 0;
}

)__BPF__";

static uint64_t time_milliseconds()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}


static
std::vector<ebpf::USDT> quic_init_usdt_probes(pid_t pid) {
  const std::vector<ebpf::USDT> probes = {
    ebpf::USDT(pid, "quicly", "connect", "trace_quicly__connect"),
    ebpf::USDT(pid, "quicly", "accept", "trace_quicly__accept"),
    ebpf::USDT(pid, "quicly", "free", "trace_quicly__free"),
    ebpf::USDT(pid, "quicly", "send", "trace_quicly__send"),
    ebpf::USDT(pid, "quicly", "receive", "trace_quicly__receive"),
    ebpf::USDT(pid, "quicly", "version_switch", "trace_quicly__version_switch"),
    ebpf::USDT(pid, "quicly", "idle_timeout", "trace_quicly__idle_timeout"),
    ebpf::USDT(pid, "quicly", "stateless_reset_receive", "trace_quicly__stateless_reset_receive"),
    ebpf::USDT(pid, "quicly", "crypto_decrypt", "trace_quicly__crypto_decrypt"),
    ebpf::USDT(pid, "quicly", "crypto_handshake", "trace_quicly__crypto_handshake"),
    ebpf::USDT(pid, "quicly", "crypto_update_secret", "trace_quicly__crypto_update_secret"),
    ebpf::USDT(pid, "quicly", "crypto_send_key_update", "trace_quicly__crypto_send_key_update"),
    ebpf::USDT(pid, "quicly", "crypto_send_key_update_confirmed", "trace_quicly__crypto_send_key_update_confirmed"),
    ebpf::USDT(pid, "quicly", "crypto_receive_key_update", "trace_quicly__crypto_receive_key_update"),
    ebpf::USDT(pid, "quicly", "crypto_receive_key_update_prepare", "trace_quicly__crypto_receive_key_update_prepare"),
    ebpf::USDT(pid, "quicly", "packet_prepare", "trace_quicly__packet_prepare"),
    ebpf::USDT(pid, "quicly", "packet_commit", "trace_quicly__packet_commit"),
    ebpf::USDT(pid, "quicly", "packet_acked", "trace_quicly__packet_acked"),
    ebpf::USDT(pid, "quicly", "packet_lost", "trace_quicly__packet_lost"),
    ebpf::USDT(pid, "quicly", "pto", "trace_quicly__pto"),
    ebpf::USDT(pid, "quicly", "cc_ack_received", "trace_quicly__cc_ack_received"),
    ebpf::USDT(pid, "quicly", "cc_congestion", "trace_quicly__cc_congestion"),
    ebpf::USDT(pid, "quicly", "ack_send", "trace_quicly__ack_send"),
    ebpf::USDT(pid, "quicly", "ping_send", "trace_quicly__ping_send"),
    ebpf::USDT(pid, "quicly", "ping_receive", "trace_quicly__ping_receive"),
    ebpf::USDT(pid, "quicly", "transport_close_send", "trace_quicly__transport_close_send"),
    ebpf::USDT(pid, "quicly", "transport_close_receive", "trace_quicly__transport_close_receive"),
    ebpf::USDT(pid, "quicly", "application_close_send", "trace_quicly__application_close_send"),
    ebpf::USDT(pid, "quicly", "application_close_receive", "trace_quicly__application_close_receive"),
    ebpf::USDT(pid, "quicly", "stream_send", "trace_quicly__stream_send"),
    ebpf::USDT(pid, "quicly", "stream_receive", "trace_quicly__stream_receive"),
    ebpf::USDT(pid, "quicly", "stream_acked", "trace_quicly__stream_acked"),
    ebpf::USDT(pid, "quicly", "stream_lost", "trace_quicly__stream_lost"),
    ebpf::USDT(pid, "quicly", "max_data_send", "trace_quicly__max_data_send"),
    ebpf::USDT(pid, "quicly", "max_data_receive", "trace_quicly__max_data_receive"),
    ebpf::USDT(pid, "quicly", "max_streams_send", "trace_quicly__max_streams_send"),
    ebpf::USDT(pid, "quicly", "max_streams_receive", "trace_quicly__max_streams_receive"),
    ebpf::USDT(pid, "quicly", "max_stream_data_send", "trace_quicly__max_stream_data_send"),
    ebpf::USDT(pid, "quicly", "max_stream_data_receive", "trace_quicly__max_stream_data_receive"),
    ebpf::USDT(pid, "quicly", "new_token_send", "trace_quicly__new_token_send"),
    ebpf::USDT(pid, "quicly", "new_token_acked", "trace_quicly__new_token_acked"),
    ebpf::USDT(pid, "quicly", "new_token_receive", "trace_quicly__new_token_receive"),
    ebpf::USDT(pid, "quicly", "handshake_done_send", "trace_quicly__handshake_done_send"),
    ebpf::USDT(pid, "quicly", "handshake_done_receive", "trace_quicly__handshake_done_receive"),
    ebpf::USDT(pid, "quicly", "streams_blocked_send", "trace_quicly__streams_blocked_send"),
    ebpf::USDT(pid, "quicly", "streams_blocked_receive", "trace_quicly__streams_blocked_receive"),
    ebpf::USDT(pid, "quicly", "new_connection_id_send", "trace_quicly__new_connection_id_send"),
    ebpf::USDT(pid, "quicly", "new_connection_id_receive", "trace_quicly__new_connection_id_receive"),
    ebpf::USDT(pid, "quicly", "retire_connection_id_send", "trace_quicly__retire_connection_id_send"),
    ebpf::USDT(pid, "quicly", "retire_connection_id_receive", "trace_quicly__retire_connection_id_receive"),
    ebpf::USDT(pid, "quicly", "data_blocked_receive", "trace_quicly__data_blocked_receive"),
    ebpf::USDT(pid, "quicly", "stream_data_blocked_receive", "trace_quicly__stream_data_blocked_receive"),
    ebpf::USDT(pid, "quicly", "ack_frequency_receive", "trace_quicly__ack_frequency_receive"),
    ebpf::USDT(pid, "quicly", "quictrace_sent", "trace_quicly__quictrace_sent"),
    ebpf::USDT(pid, "quicly", "quictrace_recv", "trace_quicly__quictrace_recv"),
    ebpf::USDT(pid, "quicly", "quictrace_send_stream", "trace_quicly__quictrace_send_stream"),
    ebpf::USDT(pid, "quicly", "quictrace_recv_stream", "trace_quicly__quictrace_recv_stream"),
    ebpf::USDT(pid, "quicly", "quictrace_recv_ack", "trace_quicly__quictrace_recv_ack"),
    ebpf::USDT(pid, "quicly", "quictrace_recv_ack_delay", "trace_quicly__quictrace_recv_ack_delay"),
    ebpf::USDT(pid, "quicly", "quictrace_lost", "trace_quicly__quictrace_lost"),
    ebpf::USDT(pid, "quicly", "quictrace_cc_ack", "trace_quicly__quictrace_cc_ack"),
    ebpf::USDT(pid, "quicly", "quictrace_cc_lost", "trace_quicly__quictrace_cc_lost"),
    ebpf::USDT(pid, "quicly", "conn_stats", "trace_quicly__conn_stats"),
    ebpf::USDT(pid, "h2o", "h3_accept", "trace_h2o__h3_accept"),
    ebpf::USDT(pid, "h2o", "h3_close", "trace_h2o__h3_close"),
    ebpf::USDT(pid, "h2o", "send_response_header", "trace_h2o__send_response_header"),

  };
  return probes;
}


struct quic_event_t {
  uint8_t id;

  union {
    struct { // quicly:connect
      uint32_t master_id;
      int64_t at;
      uint32_t version;
    } connect;
    struct { // quicly:accept
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
    } accept;
    struct { // quicly:free
      uint32_t master_id;
      int64_t at;
    } free;
    struct { // quicly:send
      uint32_t master_id;
      int64_t at;
      int state;
      char dcid[STR_LEN];
    } send;
    struct { // quicly:receive
      uint32_t master_id;
      int64_t at;
      char dcid[STR_LEN];
      uint8_t bytes[1];
      size_t bytes_len;
    } receive;
    struct { // quicly:version_switch
      uint32_t master_id;
      int64_t at;
      uint32_t new_version;
    } version_switch;
    struct { // quicly:idle_timeout
      uint32_t master_id;
      int64_t at;
    } idle_timeout;
    struct { // quicly:stateless_reset_receive
      uint32_t master_id;
      int64_t at;
    } stateless_reset_receive;
    struct { // quicly:crypto_decrypt
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t decrypted_len;
    } crypto_decrypt;
    struct { // quicly:crypto_handshake
      uint32_t master_id;
      int64_t at;
      int ret;
    } crypto_handshake;
    struct { // quicly:crypto_update_secret
      uint32_t master_id;
      int64_t at;
      int is_enc;
      uint8_t epoch;
      char label[STR_LEN];
    } crypto_update_secret;
    struct { // quicly:crypto_send_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
    } crypto_send_key_update;
    struct { // quicly:crypto_send_key_update_confirmed
      uint32_t master_id;
      int64_t at;
      uint64_t next_pn;
    } crypto_send_key_update_confirmed;
    struct { // quicly:crypto_receive_key_update
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update;
    struct { // quicly:crypto_receive_key_update_prepare
      uint32_t master_id;
      int64_t at;
      uint64_t phase;
    } crypto_receive_key_update_prepare;
    struct { // quicly:packet_prepare
      uint32_t master_id;
      int64_t at;
      uint8_t first_octet;
      char dcid[STR_LEN];
    } packet_prepare;
    struct { // quicly:packet_commit
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      int ack_only;
    } packet_commit;
    struct { // quicly:packet_acked
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      int is_late_ack;
    } packet_acked;
    struct { // quicly:packet_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } packet_lost;
    struct { // quicly:pto
      uint32_t master_id;
      int64_t at;
      size_t inflight;
      uint32_t cwnd;
      int8_t pto_count;
    } pto;
    struct { // quicly:cc_ack_received
      uint32_t master_id;
      int64_t at;
      uint64_t largest_acked;
      size_t bytes_acked;
      uint32_t cwnd;
      size_t inflight;
    } cc_ack_received;
    struct { // quicly:cc_congestion
      uint32_t master_id;
      int64_t at;
      uint64_t max_lost_pn;
      size_t inflight;
      uint32_t cwnd;
    } cc_congestion;
    struct { // quicly:ack_send
      uint32_t master_id;
      int64_t at;
      uint64_t largest_acked;
      uint64_t ack_delay;
    } ack_send;
    struct { // quicly:ping_send
      uint32_t master_id;
      int64_t at;
    } ping_send;
    struct { // quicly:ping_receive
      uint32_t master_id;
      int64_t at;
    } ping_receive;
    struct { // quicly:transport_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_send;
    struct { // quicly:transport_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      uint64_t frame_type;
      char reason_phrase[STR_LEN];
    } transport_close_receive;
    struct { // quicly:application_close_send
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_send;
    struct { // quicly:application_close_receive
      uint32_t master_id;
      int64_t at;
      uint64_t error_code;
      char reason_phrase[STR_LEN];
    } application_close_receive;
    struct { // quicly:stream_send
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t off;
      size_t len;
      int is_fin;
    } stream_send;
    struct { // quicly:stream_receive
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t off;
      size_t len;
    } stream_receive;
    struct { // quicly:stream_acked
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_acked;
    struct { // quicly:stream_lost
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
    } stream_lost;
    struct { // quicly:max_data_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_send;
    struct { // quicly:max_data_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
    } max_data_receive;
    struct { // quicly:max_streams_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_send;
    struct { // quicly:max_streams_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } max_streams_receive;
    struct { // quicly:max_stream_data_send
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t limit;
    } max_stream_data_send;
    struct { // quicly:max_stream_data_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } max_stream_data_receive;
    struct { // quicly:new_token_send
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
      uint64_t generation;
    } new_token_send;
    struct { // quicly:new_token_acked
      uint32_t master_id;
      int64_t at;
      uint64_t generation;
    } new_token_acked;
    struct { // quicly:new_token_receive
      uint32_t master_id;
      int64_t at;
      uint8_t token[STR_LEN];
      size_t token_len;
    } new_token_receive;
    struct { // quicly:handshake_done_send
      uint32_t master_id;
      int64_t at;
    } handshake_done_send;
    struct { // quicly:handshake_done_receive
      uint32_t master_id;
      int64_t at;
    } handshake_done_receive;
    struct { // quicly:streams_blocked_send
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_send;
    struct { // quicly:streams_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t limit;
      int is_unidirectional;
    } streams_blocked_receive;
    struct { // quicly:new_connection_id_send
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_send;
    struct { // quicly:new_connection_id_receive
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t retire_prior_to;
      char cid[STR_LEN];
      char stateless_reset_token[STR_LEN];
    } new_connection_id_receive;
    struct { // quicly:retire_connection_id_send
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_send;
    struct { // quicly:retire_connection_id_receive
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
    } retire_connection_id_receive;
    struct { // quicly:data_blocked_receive
      uint32_t master_id;
      int64_t at;
      uint64_t off;
    } data_blocked_receive;
    struct { // quicly:stream_data_blocked_receive
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t limit;
    } stream_data_blocked_receive;
    struct { // quicly:ack_frequency_receive
      uint32_t master_id;
      int64_t at;
      uint64_t sequence;
      uint64_t packet_tolerance;
      uint64_t max_ack_delay;
      int ignore_order;
    } ack_frequency_receive;
    struct { // quicly:quictrace_sent
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
      size_t len;
      uint8_t packet_type;
    } quictrace_sent;
    struct { // quicly:quictrace_recv
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_recv;
    struct { // quicly:quictrace_send_stream
      uint32_t master_id;
      int64_t at;
      quicly_stream_id_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_send_stream;
    struct { // quicly:quictrace_recv_stream
      uint32_t master_id;
      int64_t at;
      int64_t stream_id;
      uint64_t off;
      size_t len;
      int fin;
    } quictrace_recv_stream;
    struct { // quicly:quictrace_recv_ack
      uint32_t master_id;
      int64_t at;
      uint64_t ack_block_begin;
      uint64_t ack_block_end;
    } quictrace_recv_ack;
    struct { // quicly:quictrace_recv_ack_delay
      uint32_t master_id;
      int64_t at;
      int64_t ack_delay;
    } quictrace_recv_ack_delay;
    struct { // quicly:quictrace_lost
      uint32_t master_id;
      int64_t at;
      uint64_t pn;
    } quictrace_lost;
    struct { // quicly:quictrace_cc_ack
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_ack;
    struct { // quicly:quictrace_cc_lost
      uint32_t master_id;
      int64_t at;
      uint32_t minimum;
      uint32_t smoothed;
      uint32_t variance;
      uint32_t latest;
      uint32_t cwnd;
      size_t inflight;
    } quictrace_cc_lost;
    struct { // quicly:conn_stats
      uint32_t master_id;
      int64_t at;
      size_t size;
    } conn_stats;
    struct { // h2o:h3_accept
      uint64_t conn_id;
      uint32_t master_id;
    } h3_accept;
    struct { // h2o:h3_close
      uint64_t conn_id;
      uint32_t master_id;
    } h3_close;
    struct { // h2o:send_response_header
      uint64_t conn_id;
      uint64_t req_id;
      char name[STR_LEN];
      size_t name_len;
      char value[STR_LEN];
      size_t value_len;
      uint32_t master_id;
    } send_response_header;

    };
  };
  

static
void quic_handle_event(h2o_tracer_t *tracer, const void *data, int data_len) {
  FILE *out = tracer->out;

  const quic_event_t *event = static_cast<const quic_event_t*>(data);

  if (event->id == 1) { // sched:sched_process_exit
    exit(0);
  }

  // output JSON
  fprintf(out, "{");

  switch (event->id) {
  case 2: { // quicly:connect
    json_write_pair_n(out, STR_LIT("type"), "connect");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->connect.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->connect.at);
    json_write_pair_c(out, STR_LIT("version"), event->connect.version);
    break;
  }
  case 3: { // quicly:accept
    json_write_pair_n(out, STR_LIT("type"), "accept");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->accept.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->accept.at);
    json_write_pair_c(out, STR_LIT("dcid"), event->accept.dcid);
    break;
  }
  case 4: { // quicly:free
    json_write_pair_n(out, STR_LIT("type"), "free");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->free.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->free.at);
    break;
  }
  case 5: { // quicly:send
    json_write_pair_n(out, STR_LIT("type"), "send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->send.at);
    json_write_pair_c(out, STR_LIT("state"), event->send.state);
    json_write_pair_c(out, STR_LIT("dcid"), event->send.dcid);
    break;
  }
  case 6: { // quicly:receive
    json_write_pair_n(out, STR_LIT("type"), "receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->receive.at);
    json_write_pair_c(out, STR_LIT("dcid"), event->receive.dcid);
    json_write_pair_c(out, STR_LIT("first-octet"), event->receive.bytes[0]);
    json_write_pair_c(out, STR_LIT("bytes-len"), event->receive.bytes_len);
    break;
  }
  case 7: { // quicly:version_switch
    json_write_pair_n(out, STR_LIT("type"), "version-switch");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->version_switch.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->version_switch.at);
    json_write_pair_c(out, STR_LIT("new-version"), event->version_switch.new_version);
    break;
  }
  case 8: { // quicly:idle_timeout
    json_write_pair_n(out, STR_LIT("type"), "idle-timeout");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->idle_timeout.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->idle_timeout.at);
    break;
  }
  case 9: { // quicly:stateless_reset_receive
    json_write_pair_n(out, STR_LIT("type"), "stateless-reset-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->stateless_reset_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stateless_reset_receive.at);
    break;
  }
  case 10: { // quicly:crypto_decrypt
    json_write_pair_n(out, STR_LIT("type"), "crypto-decrypt");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_decrypt.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_decrypt.at);
    json_write_pair_c(out, STR_LIT("pn"), event->crypto_decrypt.pn);
    json_write_pair_c(out, STR_LIT("decrypted-len"), event->crypto_decrypt.decrypted_len);
    break;
  }
  case 11: { // quicly:crypto_handshake
    json_write_pair_n(out, STR_LIT("type"), "crypto-handshake");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_handshake.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_handshake.at);
    json_write_pair_c(out, STR_LIT("ret"), event->crypto_handshake.ret);
    break;
  }
  case 12: { // quicly:crypto_update_secret
    json_write_pair_n(out, STR_LIT("type"), "crypto-update-secret");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_update_secret.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_update_secret.at);
    json_write_pair_c(out, STR_LIT("is-enc"), event->crypto_update_secret.is_enc);
    json_write_pair_c(out, STR_LIT("epoch"), event->crypto_update_secret.epoch);
    json_write_pair_c(out, STR_LIT("label"), event->crypto_update_secret.label);
    break;
  }
  case 13: { // quicly:crypto_send_key_update
    json_write_pair_n(out, STR_LIT("type"), "crypto-send-key-update");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_send_key_update.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_send_key_update.at);
    json_write_pair_c(out, STR_LIT("phase"), event->crypto_send_key_update.phase);
    break;
  }
  case 14: { // quicly:crypto_send_key_update_confirmed
    json_write_pair_n(out, STR_LIT("type"), "crypto-send-key-update-confirmed");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_send_key_update_confirmed.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_send_key_update_confirmed.at);
    json_write_pair_c(out, STR_LIT("next-pn"), event->crypto_send_key_update_confirmed.next_pn);
    break;
  }
  case 15: { // quicly:crypto_receive_key_update
    json_write_pair_n(out, STR_LIT("type"), "crypto-receive-key-update");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_receive_key_update.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_receive_key_update.at);
    json_write_pair_c(out, STR_LIT("phase"), event->crypto_receive_key_update.phase);
    break;
  }
  case 16: { // quicly:crypto_receive_key_update_prepare
    json_write_pair_n(out, STR_LIT("type"), "crypto-receive-key-update-prepare");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->crypto_receive_key_update_prepare.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->crypto_receive_key_update_prepare.at);
    json_write_pair_c(out, STR_LIT("phase"), event->crypto_receive_key_update_prepare.phase);
    break;
  }
  case 17: { // quicly:packet_prepare
    json_write_pair_n(out, STR_LIT("type"), "packet-prepare");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->packet_prepare.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_prepare.at);
    json_write_pair_c(out, STR_LIT("first-octet"), event->packet_prepare.first_octet);
    json_write_pair_c(out, STR_LIT("dcid"), event->packet_prepare.dcid);
    break;
  }
  case 18: { // quicly:packet_commit
    json_write_pair_n(out, STR_LIT("type"), "packet-commit");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->packet_commit.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_commit.at);
    json_write_pair_c(out, STR_LIT("pn"), event->packet_commit.pn);
    json_write_pair_c(out, STR_LIT("len"), event->packet_commit.len);
    json_write_pair_c(out, STR_LIT("ack-only"), event->packet_commit.ack_only);
    break;
  }
  case 19: { // quicly:packet_acked
    json_write_pair_n(out, STR_LIT("type"), "packet-acked");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->packet_acked.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_acked.at);
    json_write_pair_c(out, STR_LIT("pn"), event->packet_acked.pn);
    json_write_pair_c(out, STR_LIT("is-late-ack"), event->packet_acked.is_late_ack);
    break;
  }
  case 20: { // quicly:packet_lost
    json_write_pair_n(out, STR_LIT("type"), "packet-lost");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->packet_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->packet_lost.at);
    json_write_pair_c(out, STR_LIT("pn"), event->packet_lost.pn);
    break;
  }
  case 21: { // quicly:pto
    json_write_pair_n(out, STR_LIT("type"), "pto");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->pto.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->pto.at);
    json_write_pair_c(out, STR_LIT("inflight"), event->pto.inflight);
    json_write_pair_c(out, STR_LIT("cwnd"), event->pto.cwnd);
    json_write_pair_c(out, STR_LIT("pto-count"), event->pto.pto_count);
    break;
  }
  case 22: { // quicly:cc_ack_received
    json_write_pair_n(out, STR_LIT("type"), "cc-ack-received");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->cc_ack_received.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->cc_ack_received.at);
    json_write_pair_c(out, STR_LIT("largest-acked"), event->cc_ack_received.largest_acked);
    json_write_pair_c(out, STR_LIT("bytes-acked"), event->cc_ack_received.bytes_acked);
    json_write_pair_c(out, STR_LIT("cwnd"), event->cc_ack_received.cwnd);
    json_write_pair_c(out, STR_LIT("inflight"), event->cc_ack_received.inflight);
    break;
  }
  case 23: { // quicly:cc_congestion
    json_write_pair_n(out, STR_LIT("type"), "cc-congestion");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->cc_congestion.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->cc_congestion.at);
    json_write_pair_c(out, STR_LIT("max-lost-pn"), event->cc_congestion.max_lost_pn);
    json_write_pair_c(out, STR_LIT("inflight"), event->cc_congestion.inflight);
    json_write_pair_c(out, STR_LIT("cwnd"), event->cc_congestion.cwnd);
    break;
  }
  case 24: { // quicly:ack_send
    json_write_pair_n(out, STR_LIT("type"), "ack-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->ack_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->ack_send.at);
    json_write_pair_c(out, STR_LIT("largest-acked"), event->ack_send.largest_acked);
    json_write_pair_c(out, STR_LIT("ack-delay"), event->ack_send.ack_delay);
    break;
  }
  case 25: { // quicly:ping_send
    json_write_pair_n(out, STR_LIT("type"), "ping-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->ping_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->ping_send.at);
    break;
  }
  case 26: { // quicly:ping_receive
    json_write_pair_n(out, STR_LIT("type"), "ping-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->ping_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->ping_receive.at);
    break;
  }
  case 27: { // quicly:transport_close_send
    json_write_pair_n(out, STR_LIT("type"), "transport-close-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->transport_close_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->transport_close_send.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->transport_close_send.error_code);
    json_write_pair_c(out, STR_LIT("frame-type"), event->transport_close_send.frame_type);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->transport_close_send.reason_phrase);
    break;
  }
  case 28: { // quicly:transport_close_receive
    json_write_pair_n(out, STR_LIT("type"), "transport-close-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->transport_close_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->transport_close_receive.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->transport_close_receive.error_code);
    json_write_pair_c(out, STR_LIT("frame-type"), event->transport_close_receive.frame_type);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->transport_close_receive.reason_phrase);
    break;
  }
  case 29: { // quicly:application_close_send
    json_write_pair_n(out, STR_LIT("type"), "application-close-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->application_close_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->application_close_send.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->application_close_send.error_code);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->application_close_send.reason_phrase);
    break;
  }
  case 30: { // quicly:application_close_receive
    json_write_pair_n(out, STR_LIT("type"), "application-close-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->application_close_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->application_close_receive.at);
    json_write_pair_c(out, STR_LIT("error-code"), event->application_close_receive.error_code);
    json_write_pair_c(out, STR_LIT("reason-phrase"), event->application_close_receive.reason_phrase);
    break;
  }
  case 31: { // quicly:stream_send
    json_write_pair_n(out, STR_LIT("type"), "stream-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->stream_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_send.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_send.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_send.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_send.len);
    json_write_pair_c(out, STR_LIT("is-fin"), event->stream_send.is_fin);
    break;
  }
  case 32: { // quicly:stream_receive
    json_write_pair_n(out, STR_LIT("type"), "stream-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->stream_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_receive.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_receive.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_receive.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_receive.len);
    break;
  }
  case 33: { // quicly:stream_acked
    json_write_pair_n(out, STR_LIT("type"), "stream-acked");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->stream_acked.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_acked.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_acked.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_acked.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_acked.len);
    break;
  }
  case 34: { // quicly:stream_lost
    json_write_pair_n(out, STR_LIT("type"), "stream-lost");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->stream_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_lost.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_lost.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->stream_lost.off);
    json_write_pair_c(out, STR_LIT("len"), event->stream_lost.len);
    break;
  }
  case 35: { // quicly:max_data_send
    json_write_pair_n(out, STR_LIT("type"), "max-data-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->max_data_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_data_send.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_data_send.limit);
    break;
  }
  case 36: { // quicly:max_data_receive
    json_write_pair_n(out, STR_LIT("type"), "max-data-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->max_data_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_data_receive.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_data_receive.limit);
    break;
  }
  case 37: { // quicly:max_streams_send
    json_write_pair_n(out, STR_LIT("type"), "max-streams-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->max_streams_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_streams_send.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_streams_send.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->max_streams_send.is_unidirectional);
    break;
  }
  case 38: { // quicly:max_streams_receive
    json_write_pair_n(out, STR_LIT("type"), "max-streams-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->max_streams_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_streams_receive.at);
    json_write_pair_c(out, STR_LIT("limit"), event->max_streams_receive.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->max_streams_receive.is_unidirectional);
    break;
  }
  case 39: { // quicly:max_stream_data_send
    json_write_pair_n(out, STR_LIT("type"), "max-stream-data-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->max_stream_data_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_stream_data_send.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->max_stream_data_send.stream_id);
    json_write_pair_c(out, STR_LIT("limit"), event->max_stream_data_send.limit);
    break;
  }
  case 40: { // quicly:max_stream_data_receive
    json_write_pair_n(out, STR_LIT("type"), "max-stream-data-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->max_stream_data_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->max_stream_data_receive.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->max_stream_data_receive.stream_id);
    json_write_pair_c(out, STR_LIT("limit"), event->max_stream_data_receive.limit);
    break;
  }
  case 41: { // quicly:new_token_send
    json_write_pair_n(out, STR_LIT("type"), "new-token-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->new_token_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_token_send.at);
    json_write_pair_c(out, STR_LIT("token"), event->new_token_send.token, (event->new_token_send.token_len < STR_LEN ? event->new_token_send.token_len : STR_LEN));
    json_write_pair_c(out, STR_LIT("token-len"), event->new_token_send.token_len);
    json_write_pair_c(out, STR_LIT("generation"), event->new_token_send.generation);
    break;
  }
  case 42: { // quicly:new_token_acked
    json_write_pair_n(out, STR_LIT("type"), "new-token-acked");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->new_token_acked.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_token_acked.at);
    json_write_pair_c(out, STR_LIT("generation"), event->new_token_acked.generation);
    break;
  }
  case 43: { // quicly:new_token_receive
    json_write_pair_n(out, STR_LIT("type"), "new-token-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->new_token_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_token_receive.at);
    json_write_pair_c(out, STR_LIT("token"), event->new_token_receive.token, (event->new_token_receive.token_len < STR_LEN ? event->new_token_receive.token_len : STR_LEN));
    json_write_pair_c(out, STR_LIT("token-len"), event->new_token_receive.token_len);
    break;
  }
  case 44: { // quicly:handshake_done_send
    json_write_pair_n(out, STR_LIT("type"), "handshake-done-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->handshake_done_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->handshake_done_send.at);
    break;
  }
  case 45: { // quicly:handshake_done_receive
    json_write_pair_n(out, STR_LIT("type"), "handshake-done-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->handshake_done_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->handshake_done_receive.at);
    break;
  }
  case 46: { // quicly:streams_blocked_send
    json_write_pair_n(out, STR_LIT("type"), "streams-blocked-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->streams_blocked_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->streams_blocked_send.at);
    json_write_pair_c(out, STR_LIT("limit"), event->streams_blocked_send.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->streams_blocked_send.is_unidirectional);
    break;
  }
  case 47: { // quicly:streams_blocked_receive
    json_write_pair_n(out, STR_LIT("type"), "streams-blocked-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->streams_blocked_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->streams_blocked_receive.at);
    json_write_pair_c(out, STR_LIT("limit"), event->streams_blocked_receive.limit);
    json_write_pair_c(out, STR_LIT("is-unidirectional"), event->streams_blocked_receive.is_unidirectional);
    break;
  }
  case 48: { // quicly:new_connection_id_send
    json_write_pair_n(out, STR_LIT("type"), "new-connection-id-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->new_connection_id_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_connection_id_send.at);
    json_write_pair_c(out, STR_LIT("sequence"), event->new_connection_id_send.sequence);
    json_write_pair_c(out, STR_LIT("retire-prior-to"), event->new_connection_id_send.retire_prior_to);
    json_write_pair_c(out, STR_LIT("cid"), event->new_connection_id_send.cid);
    json_write_pair_c(out, STR_LIT("stateless-reset-token"), event->new_connection_id_send.stateless_reset_token);
    break;
  }
  case 49: { // quicly:new_connection_id_receive
    json_write_pair_n(out, STR_LIT("type"), "new-connection-id-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->new_connection_id_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->new_connection_id_receive.at);
    json_write_pair_c(out, STR_LIT("sequence"), event->new_connection_id_receive.sequence);
    json_write_pair_c(out, STR_LIT("retire-prior-to"), event->new_connection_id_receive.retire_prior_to);
    json_write_pair_c(out, STR_LIT("cid"), event->new_connection_id_receive.cid);
    json_write_pair_c(out, STR_LIT("stateless-reset-token"), event->new_connection_id_receive.stateless_reset_token);
    break;
  }
  case 50: { // quicly:retire_connection_id_send
    json_write_pair_n(out, STR_LIT("type"), "retire-connection-id-send");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->retire_connection_id_send.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->retire_connection_id_send.at);
    json_write_pair_c(out, STR_LIT("sequence"), event->retire_connection_id_send.sequence);
    break;
  }
  case 51: { // quicly:retire_connection_id_receive
    json_write_pair_n(out, STR_LIT("type"), "retire-connection-id-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->retire_connection_id_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->retire_connection_id_receive.at);
    json_write_pair_c(out, STR_LIT("sequence"), event->retire_connection_id_receive.sequence);
    break;
  }
  case 52: { // quicly:data_blocked_receive
    json_write_pair_n(out, STR_LIT("type"), "data-blocked-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->data_blocked_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->data_blocked_receive.at);
    json_write_pair_c(out, STR_LIT("off"), event->data_blocked_receive.off);
    break;
  }
  case 53: { // quicly:stream_data_blocked_receive
    json_write_pair_n(out, STR_LIT("type"), "stream-data-blocked-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->stream_data_blocked_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->stream_data_blocked_receive.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->stream_data_blocked_receive.stream_id);
    json_write_pair_c(out, STR_LIT("limit"), event->stream_data_blocked_receive.limit);
    break;
  }
  case 54: { // quicly:ack_frequency_receive
    json_write_pair_n(out, STR_LIT("type"), "ack-frequency-receive");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->ack_frequency_receive.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->ack_frequency_receive.at);
    json_write_pair_c(out, STR_LIT("sequence"), event->ack_frequency_receive.sequence);
    json_write_pair_c(out, STR_LIT("packet-tolerance"), event->ack_frequency_receive.packet_tolerance);
    json_write_pair_c(out, STR_LIT("max-ack-delay"), event->ack_frequency_receive.max_ack_delay);
    json_write_pair_c(out, STR_LIT("ignore-order"), event->ack_frequency_receive.ignore_order);
    break;
  }
  case 55: { // quicly:quictrace_sent
    json_write_pair_n(out, STR_LIT("type"), "quictrace-sent");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_sent.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_sent.at);
    json_write_pair_c(out, STR_LIT("pn"), event->quictrace_sent.pn);
    json_write_pair_c(out, STR_LIT("len"), event->quictrace_sent.len);
    json_write_pair_c(out, STR_LIT("packet-type"), event->quictrace_sent.packet_type);
    break;
  }
  case 56: { // quicly:quictrace_recv
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv.at);
    json_write_pair_c(out, STR_LIT("pn"), event->quictrace_recv.pn);
    break;
  }
  case 57: { // quicly:quictrace_send_stream
    json_write_pair_n(out, STR_LIT("type"), "quictrace-send-stream");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_send_stream.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_send_stream.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->quictrace_send_stream.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->quictrace_send_stream.off);
    json_write_pair_c(out, STR_LIT("len"), event->quictrace_send_stream.len);
    json_write_pair_c(out, STR_LIT("fin"), event->quictrace_send_stream.fin);
    break;
  }
  case 58: { // quicly:quictrace_recv_stream
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv-stream");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv_stream.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv_stream.at);
    json_write_pair_c(out, STR_LIT("stream-id"), event->quictrace_recv_stream.stream_id);
    json_write_pair_c(out, STR_LIT("off"), event->quictrace_recv_stream.off);
    json_write_pair_c(out, STR_LIT("len"), event->quictrace_recv_stream.len);
    json_write_pair_c(out, STR_LIT("fin"), event->quictrace_recv_stream.fin);
    break;
  }
  case 59: { // quicly:quictrace_recv_ack
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv-ack");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv_ack.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv_ack.at);
    json_write_pair_c(out, STR_LIT("ack-block-begin"), event->quictrace_recv_ack.ack_block_begin);
    json_write_pair_c(out, STR_LIT("ack-block-end"), event->quictrace_recv_ack.ack_block_end);
    break;
  }
  case 60: { // quicly:quictrace_recv_ack_delay
    json_write_pair_n(out, STR_LIT("type"), "quictrace-recv-ack-delay");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_recv_ack_delay.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_recv_ack_delay.at);
    json_write_pair_c(out, STR_LIT("ack-delay"), event->quictrace_recv_ack_delay.ack_delay);
    break;
  }
  case 61: { // quicly:quictrace_lost
    json_write_pair_n(out, STR_LIT("type"), "quictrace-lost");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_lost.at);
    json_write_pair_c(out, STR_LIT("pn"), event->quictrace_lost.pn);
    break;
  }
  case 62: { // quicly:quictrace_cc_ack
    json_write_pair_n(out, STR_LIT("type"), "quictrace-cc-ack");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_cc_ack.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_cc_ack.at);
    json_write_pair_c(out, STR_LIT("min-rtt"), event->quictrace_cc_ack.minimum);
    json_write_pair_c(out, STR_LIT("smoothed-rtt"), event->quictrace_cc_ack.smoothed);
    json_write_pair_c(out, STR_LIT("variance-rtt"), event->quictrace_cc_ack.variance);
    json_write_pair_c(out, STR_LIT("latest-rtt"), event->quictrace_cc_ack.latest);
    json_write_pair_c(out, STR_LIT("cwnd"), event->quictrace_cc_ack.cwnd);
    json_write_pair_c(out, STR_LIT("inflight"), event->quictrace_cc_ack.inflight);
    break;
  }
  case 63: { // quicly:quictrace_cc_lost
    json_write_pair_n(out, STR_LIT("type"), "quictrace-cc-lost");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->quictrace_cc_lost.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->quictrace_cc_lost.at);
    json_write_pair_c(out, STR_LIT("min-rtt"), event->quictrace_cc_lost.minimum);
    json_write_pair_c(out, STR_LIT("smoothed-rtt"), event->quictrace_cc_lost.smoothed);
    json_write_pair_c(out, STR_LIT("variance-rtt"), event->quictrace_cc_lost.variance);
    json_write_pair_c(out, STR_LIT("latest-rtt"), event->quictrace_cc_lost.latest);
    json_write_pair_c(out, STR_LIT("cwnd"), event->quictrace_cc_lost.cwnd);
    json_write_pair_c(out, STR_LIT("inflight"), event->quictrace_cc_lost.inflight);
    break;
  }
  case 65: { // quicly:conn_stats
    json_write_pair_n(out, STR_LIT("type"), "conn-stats");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn"), event->conn_stats.master_id);
    json_write_pair_c(out, STR_LIT("time"), event->conn_stats.at);
    json_write_pair_c(out, STR_LIT("size"), event->conn_stats.size);
    break;
  }
  case 69: { // h2o:h3_accept
    json_write_pair_n(out, STR_LIT("type"), "h3-accept");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn-id"), event->h3_accept.conn_id);
    json_write_pair_c(out, STR_LIT("conn"), event->h3_accept.master_id);
    json_write_pair_c(out, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 70: { // h2o:h3_close
    json_write_pair_n(out, STR_LIT("type"), "h3-close");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn-id"), event->h3_close.conn_id);
    json_write_pair_c(out, STR_LIT("conn"), event->h3_close.master_id);
    json_write_pair_c(out, STR_LIT("time"), time_milliseconds());
    break;
  }
  case 79: { // h2o:send_response_header
    json_write_pair_n(out, STR_LIT("type"), "send-response-header");
    json_write_pair_c(out, STR_LIT("seq"), ++seq);
    json_write_pair_c(out, STR_LIT("conn-id"), event->send_response_header.conn_id);
    json_write_pair_c(out, STR_LIT("req-id"), event->send_response_header.req_id);
    json_write_pair_c(out, STR_LIT("name"), event->send_response_header.name);
    json_write_pair_c(out, STR_LIT("name-len"), event->send_response_header.name_len);
    json_write_pair_c(out, STR_LIT("value"), event->send_response_header.value);
    json_write_pair_c(out, STR_LIT("value-len"), event->send_response_header.value_len);
    json_write_pair_c(out, STR_LIT("conn"), event->send_response_header.master_id);
    json_write_pair_c(out, STR_LIT("time"), time_milliseconds());
    break;
  }

  default:
    std::abort();
  }

  fprintf(out, "}\n");
}


static void quic_handle_lost(h2o_tracer_t *tracer, uint64_t lost) {
  fprintf(tracer->out, "{"
    "\"type\":\"h2olog-event-lost\","
    "\"seq\":%" PRIu64 ","
    "\"time\":%" PRIu64 ","
    "\"lost\":%" PRIu64
    "}\n",
    ++seq, time_milliseconds(), lost);
}

static const char *quic_bpf_ext() {
  return bpf_text;
}

void init_quic_tracer(h2o_tracer_t * tracer) {
  tracer->handle_event = quic_handle_event;
  tracer->handle_lost = quic_handle_lost;
  tracer->init_usdt_probes = quic_init_usdt_probes;
  tracer->bpf_text = quic_bpf_ext;
}

