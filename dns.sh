#!/usr/bin/env bash
# 一键启停 DNS 控制台，并查看日志。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$ROOT/data/console.pid"
LOG_FILE="$ROOT/data/console.log"
HOST="127.0.0.1"
PORT="8080"
PY="$ROOT/.venv/bin/python"

usage() {
  cat <<EOF
用法: ./dns.sh <命令>

  start      后台启动。已经在跑则不动
  stop       停止本项目占用 ${PORT} 的控制台
  restart    先停止再启动
  status     看是否在运行
  logs       最近 80 行日志
  logs 200   最近 200 行
  logs -f    持续看日志
EOF
}

need_python() {
  if [[ ! -x "$PY" ]]; then
    echo "没找到 $PY。先在项目目录执行: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
  fi
}

listener_pid() {
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | head -n 1 || true
}

pid_cwd() {
  lsof -a -p "$1" -d cwd -Fn 2>/dev/null | awk '/^n/ {print substr($0, 2); exit}'
}

is_ours() {
  local pid="$1"
  local cwd cmd
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  cwd="$(pid_cwd "$pid")"
  cmd="$(ps -p "$pid" -o command= 2>/dev/null || true)"
  [[ "$cwd" == "$ROOT" ]] || return 1
  local lower
  lower="$(printf '%s' "$cmd" | tr '[:upper:]' '[:lower:]')"
  [[ "$lower" == *python* && "$lower" == *"-m app"* ]]
}

current_pid() {
  local pid listen
  if [[ -f "$PID_FILE" ]]; then
    pid="$(tr -d '[:space:]' <"$PID_FILE" || true)"
    if is_ours "$pid"; then
      echo "$pid"
      return
    fi
  fi
  listen="$(listener_pid)"
  if is_ours "$listen"; then
    echo "$listen"
  fi
}

wait_until_gone() {
  local pid="$1"
  local i
  for i in $(seq 1 25); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  return 1
}

cmd_start() {
  need_python
  mkdir -p "$ROOT/data"
  local pid other
  pid="$(current_pid || true)"
  if [[ -n "$pid" ]]; then
    echo "已经在运行，pid ${pid}，http://${HOST}:${PORT}"
    return 0
  fi
  other="$(listener_pid)"
  if [[ -n "$other" ]]; then
    echo "端口 ${PORT} 已被其他进程占用，pid ${other}" >&2
    exit 1
  fi
  (
    cd "$ROOT"
    DNS_LOG_STDOUT=0 nohup "$PY" -m app >>"$LOG_FILE" 2>&1 &
    echo $! >"$PID_FILE"
  )
  pid="$(tr -d '[:space:]' <"$PID_FILE")"
  local i
  for i in $(seq 1 30); do
    if [[ -n "$(listener_pid)" ]]; then
      echo "已启动，http://${HOST}:${PORT}"
      echo "日志：$LOG_FILE"
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "启动失败，最近日志：" >&2
      tail -n 40 "$LOG_FILE" >&2 || true
      rm -f "$PID_FILE"
      exit 1
    fi
    sleep 0.2
  done
  echo "进程已拉起，端口还没就绪。执行 ./dns.sh logs 查看。" >&2
}

cmd_stop() {
  local pid
  pid="$(current_pid || true)"
  if [[ -z "$pid" ]]; then
    rm -f "$PID_FILE"
    echo "没有在运行"
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  if ! wait_until_gone "$pid"; then
    kill -9 "$pid" 2>/dev/null || true
    wait_until_gone "$pid" || true
  fi
  rm -f "$PID_FILE"
  echo "已停止"
}

cmd_status() {
  local pid
  pid="$(current_pid || true)"
  if [[ -n "$pid" ]]; then
    echo "运行中  pid ${pid}  http://${HOST}:${PORT}"
    echo "日志  $LOG_FILE"
    return 0
  fi
  echo "没有在运行"
}

cmd_logs() {
  local arg="${1:-}"
  if [[ ! -f "$LOG_FILE" ]]; then
    echo "还没有日志。启动后会写到 $LOG_FILE"
    return 0
  fi
  if [[ "$arg" == "-f" ]]; then
    tail -n 80 -f "$LOG_FILE"
  elif [[ -n "$arg" ]]; then
    tail -n "$arg" "$LOG_FILE"
  else
    tail -n 80 "$LOG_FILE"
  fi
}

case "${1:-}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_stop; cmd_start ;;
  status) cmd_status ;;
  logs) cmd_logs "${2:-}" ;;
  *) usage; exit 1 ;;
esac
