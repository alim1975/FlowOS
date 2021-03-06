#ifndef __TCP_OUT_H_
#define __TCP_OUT_H_

#include "mtcp.h"
#include "tcp_stream.h"

enum ack_opt
{
  ACK_OPT_NOW, 
  ACK_OPT_AGGREGATE, 
  ACK_OPT_WACK
};

int SendTCPPacketStandalone(struct mtcp_manager *mtcp, 
			    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
			    uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
			    uint8_t *payload, uint16_t payloadlen, 
			    uint32_t cur_ts, uint32_t echo_ts);

int SendTCPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream,
		  uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen);

inline int WriteTCPControlList(mtcp_manager_t mtcp, 
			       struct mtcp_sender *sender, uint32_t cur_ts, int thresh);

inline int WriteTCPDataList(mtcp_manager_t mtcp, 
			    struct mtcp_sender *sender, uint32_t cur_ts, int thresh);

inline int WriteTCPACKList(mtcp_manager_t mtcp, 
			   struct mtcp_sender *sender, uint32_t cur_ts, int thresh);

inline void AddtoControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts);

inline void AddtoSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

inline void RemoveFromControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

inline void RemoveFromSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

inline void RemoveFromACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream);

inline void EnqueueACK(mtcp_manager_t mtcp, 
		       tcp_stream *cur_stream, uint32_t cur_ts, uint8_t opt);

inline void DumpControlList(mtcp_manager_t mtcp, struct mtcp_sender *sender);

#endif /* __TCP_OUT_H_ */
