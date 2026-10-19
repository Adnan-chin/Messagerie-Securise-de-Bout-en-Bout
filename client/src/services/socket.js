export function connect(token, onFrame, url = 'ws://localhost:3000/ws') {
    const ws = new WebSocket(url);
    ws.onopen = () => ws.send(JSON.stringify({ type: 'auth', token }));
    ws.onmessage = (e) => onFrame(JSON.parse(e.data));
    return {
        send: (frame) => ws.send(JSON.stringify(frame)), close: () =>
            ws.close(), ws
    };
}