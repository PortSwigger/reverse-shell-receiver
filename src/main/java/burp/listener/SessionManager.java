package burp.listener;

import burp.IBurpExtenderCallbacks;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Manages multiple concurrent reverse shell sessions.
 */
public class SessionManager {

    public interface ManagerListener {
        void onSessionAdded(ShellSession session);
        void onSessionSelected(ShellSession session);
        void onSessionRemoved(ShellSession session);
        void onSessionStateChanged();
    }

    private final List<ShellSession> sessions = new ArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(1);
    private ShellSession activeSession;
    private ManagerListener listener;
    private final ExecutorService executor;
    private final IBurpExtenderCallbacks callbacks;

    public SessionManager(ExecutorService executor) {
        this(executor, null);
    }

    public SessionManager(ExecutorService executor, IBurpExtenderCallbacks callbacks) {
        this.executor = executor;
        this.callbacks = callbacks;
    }

    public void setListener(ManagerListener listener) {
        this.listener = listener;
    }

    public synchronized ShellSession registerNewSession(Socket socket) throws IOException {
        int id = idCounter.getAndIncrement();
        ShellSession session = new ShellSession(id, socket, callbacks, new ShellSession.SessionEventListener() {
            @Override
            public void onSessionOutput(ShellSession s, String text) {
                if (listener != null) listener.onSessionStateChanged();
            }

            @Override
            public void onSessionTerminated(ShellSession s) {
                if (listener != null) listener.onSessionStateChanged();
            }

            @Override
            public void onPathUpdated(ShellSession s, String newPath) {
                if (listener != null) listener.onSessionStateChanged();
            }
        });

        sessions.add(session);
        this.activeSession = session;
        session.startReading(executor);

        if (listener != null) {
            listener.onSessionAdded(session);
            listener.onSessionSelected(session);
        }
        return session;
    }

    public synchronized List<ShellSession> getAllSessions() {
        return Collections.unmodifiableList(new ArrayList<>(sessions));
    }

    public synchronized ShellSession getActiveSession() {
        return activeSession;
    }

    public synchronized void setActiveSession(ShellSession session) {
        if (session != null && sessions.contains(session)) {
            this.activeSession = session;
            if (listener != null) {
                listener.onSessionSelected(session);
            }
        }
    }

    public synchronized void selectSessionById(int id) {
        for (ShellSession s : sessions) {
            if (s.getId() == id) {
                setActiveSession(s);
                break;
            }
        }
    }

    public synchronized void closeSession(int id) {
        ShellSession target = null;
        for (ShellSession s : sessions) {
            if (s.getId() == id) {
                target = s;
                break;
            }
        }
        if (target != null) {
            target.close();
            sessions.remove(target);
            if (activeSession == target) {
                activeSession = getNextActiveSession();
                if (listener != null && activeSession != null) {
                    listener.onSessionSelected(activeSession);
                }
            }
            if (listener != null) {
                listener.onSessionRemoved(target);
                listener.onSessionStateChanged();
            }
        }
    }

    private ShellSession getNextActiveSession() {
        for (ShellSession s : sessions) {
            if (s.isActive()) return s;
        }
        return sessions.isEmpty() ? null : sessions.get(sessions.size() - 1);
    }

    public synchronized void closeAll() {
        for (ShellSession s : sessions) {
            s.close();
        }
        sessions.clear();
        activeSession = null;
        if (listener != null) {
            listener.onSessionStateChanged();
        }
    }

    public synchronized int getActiveSessionCount() {
        int count = 0;
        for (ShellSession s : sessions) {
            if (s.isActive()) count++;
        }
        return count;
    }
}
