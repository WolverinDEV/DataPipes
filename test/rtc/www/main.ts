if(window.require) {
    window.$ = require("jquery");
}

let connection: PeerConnection;

let button = $("#connect");

let current_track: RTCRtpSender;

let _auto_stream = undefined;
let audio_stream = (): AudioContext => {
    if(_auto_stream) return _auto_stream as AudioContext;
    _auto_stream = new AudioContext();
    return _auto_stream;
}

let disable_console = 1; //Useable when you've enabled verbose output within the browser

button.on('click', () => {
    audio_stream();
    if(connection) {
        connection.peer.close();
        connection.socket.close();
        connection = undefined;
    }

    let config = new PeerConnectionConfig();
    config.open_data_channel = true;
    config.open_audio_channel = true;

    connect_peer(config).then(c => connection = c, error => {
        console.log("Got connect error %o", error);
    });
});

$("#disconnect").on('click', event => {
    if(connection) {
        connection.peer.close();
        connection.socket.close();
        connection = undefined;
    }
});

$("#send").on('click', () => {
    let message = $("#message").val().toString();
    console.log("Send message: %s", message);

    if(connection && connection.data_channels.length)
        connection.data_channels[0].send(message);
    else
        console.log("Missing channel!");
});

class PeerConnectionConfig {
    open_data_channel: boolean = false;
    open_audio_channel: boolean = false;
}

let track;

class RemoteSource {
    stream: MediaStream;
    media_stream: MediaStreamAudioSourceNode;
    audio: HTMLAudioElement;

    script_prcessor: ScriptProcessorNode;
}

let remote_sources: RemoteSource[] = [];

class PeerConnection {
    config: PeerConnectionConfig;

    socket: WebSocket;
    peer: RTCPeerConnection;

    data_channels: RTCDataChannel[] = [];

    initialized_peer() : boolean {
        const config = { /*iceServers: [{ url: 'stun:stun.l.google.com:19302' }]*/ };
        this.peer = new RTCPeerConnection(config);

        this.peer.ontrack = event => {
            console.log("[RTC] Got new track %o (%o | %o) | %o", event.track.id, event.track.label, event.track, event.track.kind);
            event.track.onended = e => {
                console.log("[RTC] Track %o ended (%o)", event.track.id, e.error);
            }
            event.track.onmute = e => {
                console.log("[RTC] Track %o muted", event.track.id);
            }
            event.track.onunmute = e => {
                console.log("[RTC] Track %o unmuted", event.track.id);
            }
            event.track.onoverconstrained = e => {
                console.log("[RTC] Track %o onoverconstrained", event.track.id);
            }
        };

        this.peer.onnegotiationneeded = event => {
            console.log("NEGOT NEEDED!");
        }
        this.peer.onconnectionstatechange = event => {
            console.log("[RTC] Connection state change %o (%o)", event.eventPhase, event);
        };
        this.peer.onicecandidateerror = event => {
            console.log("[RTC][ICE] Failed to setup candidate %s (%s) (%o | %s)", event.hostCandidate, event.url, event.errorCode, event.errorText);
        };
        this.peer.oniceconnectionstatechange = event => {
            console.log("[RTC][ICE] Connection state change %o (%o)", event.eventPhase, event);
        };
        this.peer.onicegatheringstatechange = event => {
            console.log("[RTC][ICE] Gathering state change %o (%o)", event.eventPhase, event);
        };
        this.peer.onicecandidate = (event) => {
            console.log("[RTC][ICE][LOCAL] Got new candidate %s (%o)", event.candidate, event);
            if (event) {
                if(event.candidate)
                    this.socket.send(JSON.stringify({
                        type: 'candidate',
                        msg: event.candidate
                    }));
                else
                    this.socket.send(JSON.stringify({
                        type: 'candidate_finish'
                    }));
            }
        };

        this.peer.onaddstream = event => {
            console.log("[RTC] Got a new stream %o (%o)", event.stream.id, event);

            event.stream.onactive = e => {
                console.log("[RTC][STREAM] Stream %o got active", event.stream.id);
            };
            event.stream.oninactive = e => {
                console.log("[RTC][STREAM] Stream %o got inactive", event.stream.id);
            }
            event.stream.onaddtrack = e => {
                console.log("[RTC][STREAM] Stream %o got a new track %o", event.stream.id, e.track.id);
            }
            event.stream.onremovetrack = e => {
                console.log("[RTC][STREAM] Stream %o removed the track %o", event.stream.id, e.track.id);
            }

            let handle = new RemoteSource();
            handle.stream = event.stream;

            let context = audio_stream();
            handle.media_stream = context.createMediaStreamSource(event.stream);
            handle.script_prcessor = context.createScriptProcessor(1024,  2, 2);
            //handle.media_stream.connect(handle.script_prcessor);

            handle.script_prcessor.addEventListener('audioprocess', ev => {
                if(!disable_console) {
                    let buffer = ev.inputBuffer.getChannelData(0);
                    let sum = 0;
                    for(let c of buffer)
                        sum += c;
                    console.log("Got buffer sum of %o with length %o", sum, buffer.length);
                }
                for(let channel = 0; channel < ev.outputBuffer.numberOfChannels; channel++) {
                    ev.outputBuffer.copyToChannel(ev.inputBuffer.getChannelData(channel), channel);
                }
            });
            handle.script_prcessor.connect(context.destination);

            handle.audio = new Audio();
            try {
                handle.audio.srcObject = event.stream;
            } catch(_) {
                handle.audio.src = (URL || webkitURL || mozURL).createObjectURL(event.stream);
            }
            remote_sources.push(handle);
        };
        this.peer.onremovestream = event => {
            console.log("[RTC] Removed a stream %o (%o)", event.stream.id, event);
        };

        this.peer.ondatachannel = event => {
            console.log("[RTC] Got new channel (Label: %s Id: %o)", event.channel.label, event.channel.id);
            this.initialize_data_channel(event.channel);
        };


        if(this.config.open_data_channel) {
            let dataChannel = this.peer.createDataChannel('main', { ordered: false, maxRetransmits: 0 });
            this.initialize_data_channel(dataChannel);
        }

        let sdpConstraints: RTCOfferOptions = {};
        sdpConstraints.offerToReceiveAudio = this.config.open_audio_channel;
        sdpConstraints.offerToReceiveVideo = false;


        navigator.mediaDevices.getUserMedia({ audio: true, video: false })
            .then(stream => {
                console.log("[GOT MIC!] %o", stream.getAudioTracks());
                if(this.config.open_audio_channel) {
                    this.peer.addStream(stream);
                }
                /*
                current_track = this.peer.addTrack(stream.getAudioTracks()[0]);
                console.log("Response: %o", current_track);
                current_track.onerror = error => {
                    console.log("[RTC][TRACK] Got error %o", error);
                }
                current_track.onssrcconflict = error => {
                    console.log("[RTC][TRACK] Got ssrc conflict %o", error);
                }
                */
                //let s = context.createMediaStreamSource(stream);
                //s.connect(context.destination);
                
                //document.getElementById("local_video").srcObject = stream;

                this.peer.createOffer(sdp => {
                    console.log("Got SDP: %s", sdp.sdp);
                    this.peer.setLocalDescription(sdp).then(() => {
                        console.log("[RTC] Got local sdp. Sending to partner");
                        this.socket.send(JSON.stringify({
                            type: "offer",
                            msg: sdp
                        }));
                    });
                }, () => {
                    console.log("[RTC] Failed to setup peer!");
                }, sdpConstraints);
            })
            .catch(function(err) {
                /* handle the error */
            });
        return true;
    }

    private initialize_data_channel(channel: RTCDataChannel) {
        channel.onmessage = event => {
            console.log("[DC] Got new message on %s channel: %o", channel.label, event.data);
        };
        channel.onopen = event => {
            console.log("[DC] Channel %s opened!", channel.label);
        };
        channel.onclose = event => {
            console.log("[DC] Channel %s closed!", channel.label);
        };
        channel.onerror = event => {
            console.log("[DC] On channel %s occured an error: %o", channel.label, event);
        };

        this.data_channels.push(channel);
    }
}

/*

 */

function connect_peer(config?: PeerConnectionConfig) : Promise<PeerConnection> {
    if(!config) config = new PeerConnectionConfig();

    return new Promise<PeerConnection>((resolve, reject) => {
        let result = new PeerConnection();
        result.config = config;

        result.socket = new WebSocket("wss://192.168.43.141:1111");
        //result.socket = new WebSocket("wss://felix.did.science:1111");

        result.socket.onopen = event => {
            console.log("[WS] WebSocket connected!");
            result.initialized_peer();
            resolve(result);
        };

        result.socket.onclose = event => {
            console.log("[WS] WebSocket disconnected (%o)!", event.reason);
        };

        result.socket.onerror = event => {
            console.log("[WS] Got error %s!", event.type);
        };

        let candidate_buffer = [];
        let candidate_apply = candidate => {
            result.peer.addIceCandidate(candidate).then(any => {
                console.log("[RTC][ICE][REMOTE] Sucessfully setupped candidate %o", candidate);
            }).catch(error => {
                console.log("[RTC][ICE][REMOTE] Failed to add candidate %o", error);
            });
        };
        result.socket.onmessage = event => {
            let data = JSON.parse(event.data);
            if(data["type"] == "candidate") {
                if(candidate_buffer) {
                    candidate_buffer.push(new RTCIceCandidate(data["msg"]));
                } else candidate_apply(new RTCIceCandidate(data["msg"]));
            } else if(data["type"] == "answer") {
                console.log("[RTC][SDP] Setting remote answer!");
                result.peer.setRemoteDescription(new RTCSessionDescription(data["msg"])).then(() => {
                    console.log("[RTC][SDP] Remote answer set!");
                    for(let can of candidate_buffer)
                        candidate_apply(can);
                    candidate_buffer = undefined;
                }).catch(error => {
                    console.log("Failed to set remote exception %o", error);
                });
            } else {
                console.log("Invalid message type %o", data["type"]);
            }
        };
    });
}