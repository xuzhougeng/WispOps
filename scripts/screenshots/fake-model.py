#!/usr/bin/env python3
"""A chat-completions endpoint on 127.0.0.1 that plays one scripted conversation.

Only for the README's screenshots (see `take.sh`): asked which disk is filling up, it
inspects the fleet, diagnoses gpu-02's /data, and proposes a cleanup, which the window
then holds for approval. The tools really run, against fake-ssh.py. Which step comes
next is told by how many tool results the request carries.

    fake-model.py <port-file>     writes the port it listens on, then serves until killed
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STEPS = [
    ("先巡检全部服务器，找出磁盘最紧张的那台。", "ops_inspect", {"targets": "all"}),
    ("gpu-02 的 /data 已用 93%，一个月前还是 70%，每天涨不到 1 个百分点，照这样九天左右写满。storage-01 从三次巡检前起连不上，稍后单独看。\n\n接下来以 root 对 gpu-02 的 /data 做磁盘诊断，看是什么在涨。", "ops_disk", {"host": "gpu-02", "path": "/data", "sudo": True}),
    (
        "**gpu-02:/data**（27.3T，剩 1.9T）主要被这些占着：\n\n"
        "| 目录 | 大小 | 一周增长 | 判断 |\n|---|---|---|---|\n"
        "| `datasets/` | 9.0T | — | 共享数据集，不动 |\n"
        "| `projects/alice/checkpoints` | 3.2T | +650G | alice 的训练（PID 3101）正在写，先问本人 |\n"
        "| `scratch/tmp-eval` | 3.2T | **+1.5T** | 评测的中间结果，最近 14 天没有写入，没有进程打开 |\n\n"
        "建议先清掉 `scratch/tmp-eval` 下 14 天未改动的运行目录，约可释放 2.6T，/data 会降到 84% 左右。"
        "这是破坏性操作，需要你批准；清理后我会再诊断一次核对释放的空间。",
        "ops_exec",
        {"targets": "gpu-02", "sudo": True, "command": "find /data/scratch/tmp-eval -mindepth 1 -maxdepth 1 -type d -mtime +14 -exec rm -rf {} +", "reason": "清理 14 天未改动的评测中间结果，释放 /data 约 2.6T；目录下没有进程打开的文件"},
    ),
    ("（演示到此为止。）", None, None),
]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        done = sum(1 for message in body.get("messages", []) if message.get("role") == "tool")
        text, tool, args = STEPS[min(done, len(STEPS) - 1)]
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()

        def send(delta, finish=None):
            chunk = {"id": "demo", "object": "chat.completion.chunk", "model": "demo", "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode())
            self.wfile.flush()

        send({"role": "assistant", "content": ""})
        for at in range(0, len(text), 12):
            send({"content": text[at:at + 12]})
        if tool:
            send({"tool_calls": [{"index": 0, "id": f"call_{done + 1}", "type": "function", "function": {"name": tool, "arguments": json.dumps(args, ensure_ascii=False)}}]})
        send({}, "tool_calls" if tool else "stop")
        self.wfile.write(b"data: [DONE]\n\n")


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as file:
    file.write(str(server.server_address[1]))
server.serve_forever()
