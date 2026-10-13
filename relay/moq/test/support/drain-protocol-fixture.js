// Controlled protocol boundaries for the provider's actual JS lifecycle. The
// control listener, scope registry, charging and close logic stay production.
export function deferred() { return Promise.withResolvers(); }

export class Http3Server {
  static current;
  streams = new Map();
  ready = Promise.resolve();
  stopped = deferred();
  closed = this.stopped.promise;
  streamCancel = null;
  constructor() { Http3Server.current = this; }
  startServer() {}
  stopServer() { this.stopped.resolve(); }
  setRequestCallback(callback) { this.requestCallback = callback; }
  sessionStream(path) {
    const stream = new ReadableStream({
      start: controller => { this.streams.set(path, controller); },
      cancel: () => {
        this.streams.delete(path);
        return this.streamCancel?.promise;
      },
    });
    return stream;
  }
  onHttpWTSessionVisitor(args) {
    args.session.jsobj = args.session.transport;
    this.streams.get(args.path)?.enqueue(args.session.transport);
  }
  async admit(secret, transport) {
    const path = `/${secret}`;
    const result = await this.requestCallback({header: {
      ':path': path, 'wt-available-protocols': ['moqt-16'],
    }});
    if (result.status === 200) this.onHttpWTSessionVisitor({path, session: {transport}});
    return result.status;
  }
}

export const quicheLoaded = Promise.resolve();

export class ProtocolTransport {
  ready = Promise.resolve();
  nativeClosed = deferred();
  closed = this.nativeClosed.promise;
  accepts = deferred();
  info = deferred();
  groups = [];
  nextGroup = deferred();
  readsStarted = deferred();
  acceptStarted = deferred();
  infoStarted = deferred();
  consumed = 0;
  published = 0;
  ignoreInfoClose = false;
  ignoreGroupClose = false;
  constructor({pauseAccept = false} = {}) {
    this.connection = {
      closed: this.closed,
      close: () => this.close(),
      consume: () => {
        this.consumed++;
        return {close: () => this.closeIncoming(), subscribe: () => this.incoming};
      },
      publish: () => { this.published++; },
    };
    this.incoming = {
      info: () => { this.infoStarted.resolve(); return this.info.promise; },
      recvGroup: () => {
        this.readsStarted.resolve();
        return this.groups.length ? Promise.resolve(this.groups.shift()) : this.nextGroup.promise;
      },
      close: () => this.closeIncoming(),
    };
    if (!pauseAccept) this.accepts.resolve(this.connection);
  }
  closeIncoming() {
    if (!this.ignoreInfoClose) this.info.resolve({});
    if (!this.ignoreGroupClose) this.nextGroup.resolve(undefined);
  }
  close() { this.nativeClosed.resolve(); }
}

export const Connection = {
  accept: transport => { transport.acceptStarted.resolve(); return transport.accepts.promise; },
};

export class FrameGroup {
  nextFrame = deferred();
  readStarted = deferred();
  ignoreClose = false;
  readFrame() { this.readStarted.resolve(); return this.nextFrame.promise; }
  close() { if (!this.ignoreClose) this.nextFrame.resolve(undefined); }
}

export const tracks = [];
export const Broadcast = {Producer: class {
  close() {}
  insertTrack() {}
  createTrack() {
    const track = {
      appended: 0, writes: [], closed: false,
      appendGroup() {
        this.appended++;
        return {writeFrame: frame => this.writes.push(frame), close() {}};
      },
      close() { this.closed = true; },
    };
    tracks.push(track);
    return track;
  }
}};
