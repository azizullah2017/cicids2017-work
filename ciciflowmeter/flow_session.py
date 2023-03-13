import csv
import csv
import json
from collections import defaultdict
import logging
import socket
import gc


from scapy.sessions import DefaultSession

from features.context.packet_direction import PacketDirection
from features.context.packet_flow_key import get_packet_flow_key
from flow import Flow

EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100

hostName = socket.gethostname()
log_extras = {'hostname' : hostName}


# define custom traceback filter to suppress traceback outputs to log
class TracebackInfoFilter(logging.Filter):
    """Clear or restore the exception on log records"""
    def __init__(self, clear=True):
        self.clear = clear
    def filter(self, record):
        if self.clear:
            record._exc_info_hidden, record.exc_info = record.exc_info, None
            # clear the exception traceback text cache, if created.
            record.exc_text = None
        elif hasattr(record, "_exc_info_hidden"):
            record.exc_info = record._exc_info_hidden
            del record._exc_info_hidden
        return True


# setup custom logger
logger = logging.getLogger("pcap_features-v1")
handler = logging.FileHandler('/var/log/pcap.log')
formatter = logging.Formatter('%(hostname)s %(processName)s: %(levelname)s %(name)s: %(message)s')
handler.setFormatter(formatter)
handler.addFilter(TracebackInfoFilter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)




class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        # self.csv_line = 0
        self.output_mode = "flow"
        # if self.output_mode == "flow":
        #     output = open(self.output_file, "w")
        #     self.csv_writer = csv.writer(output)

        self.packets_count = 0

        self.clumped_flows_per_label = defaultdict(list)

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        print(type(packet))
        # return
        # print("===============================")
        print("on_packet_received", self.packets_count)
        # print("===============================")

        count = 0
        direction = PacketDirection.FORWARD

        # if self.output_mode != "flow":
        #     if "TCP" not in packet:
        #         return
        #     elif "UDP" not in packet:
        #         return

        try:
            # Creates a key variable to check, get dest_ip, src_ip, src_port, dest_port
            packet_flow_key = get_packet_flow_key(packet, direction)
            # print(packet_flow_key)
            flow = self.flows.get((packet_flow_key, count))
            # print(flow)
        except Exception:
            return

        self.packets_count += 1

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break
        elif "F" in str(packet.flags):
            # If it has FIN flag then early collect flow and continue
            # flow.add_packet(packet.flags)
            flow.add_packet(packet, direction)
            self.garbage_collect(packet.time)
            return

        flow.add_packet(packet, direction)
        # print(self.url_model)
        # if not self.url_model:
        GARBAGE_COLLECT_PACKETS = 10000

        if self.packets_count % GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 and self.output_mode == "flow"
        ):
            self.garbage_collect(packet.time)

    def get_flows(self) -> list:
        return self.flows.values()

    def garbage_collect(self, latest_time) -> None:
        # TODO: Garbage Collection / Feature Extraction should have a separate thread
        try:
            print("==========================================")
            # if not self.url_model:
            print("Garbage Collection Began. Flows = {}".format(len(self.flows)))
            keys = list(self.flows.keys())
            for k in keys:
                flow = self.flows.get(k)

                if (
                    latest_time is None
                    or latest_time - flow.latest_timestamp > EXPIRED_UPDATE
                    # or flow.duration > 90
                    or flow.duration > 1

                ):
                    data = flow.get_data()

                    packet_parsed = json.dumps(data)
                    # print(type(data.values()))
                    # print(list(data.values()))
                    # packet_parsed = ",  ".join(map(str, list(data.values())))
                    print(packet_parsed)
                    logger.info(packet_parsed, extra = log_extras) # log netflow data
                    gc.collect()

                    # if self.csv_line == 0:
                    #     self.csv_writer.writerow(data.keys())

                    # self.csv_writer.writerow(data.values())
                    # self.csv_line += 1

                    del self.flows[k]
            # if not self.url_model:
            print("Garbage Collection Finished. Flows = {}".format(len(self.flows)))
        except Exception as e:
            print(e)

# def generate_session_class():
#     # return type(
#     #     "NewFlowSession",
#     #     (FlowSession,),
#     #     {
#     #         "output_mode": output_mode,
#     #         "output_file": output_file,
#     #         "url_model": url_model,
#     #     },
#     # )
#     return type(
#         "NewFlowSession",
#         (FlowSession,),
#         {
#             # "output_mode": 'flow',
#             # "output_file": 'flows1.csv',
#             # "url_model": None,
#         },
#     )


# NewFlowSession = generate_session_class()

# # # obj = FlowSession()
from scapy.all import *
sniff(session=FlowSession)

# sniff(session=NewFlowSession)
