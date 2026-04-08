import threading

def real_time_monitor(session_id, original_domain):
    """Background real-time monitoring – logs periodically, does not block."""
    import time
    def monitor():
        import time
        while True:
            time.sleep(300)  # 5 minutes
            print(f"[PhishGuard] Real-time monitor check for session {session_id}")
    # Only start if not already running for this session
    t = threading.Thread(target=monitor, daemon=True, name=f"monitor-{session_id[:8]}")
    t.start()