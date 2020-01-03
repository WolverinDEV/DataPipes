if (window.require) {
    window.$ = require("jquery");
}
var connection;
var button = $("#connect");
var current_track;
var _auto_stream = undefined;
var audio_stream = function () {
    if (_auto_stream)
        return _auto_stream;
    _auto_stream = new AudioContext();
    return _auto_stream;
};
var disable_console = 1; //Useable when you've enabled verbose output within the browser
button.on('click', function () {
    audio_stream();
    if (connection) {
        connection.peer.close();
        connection.socket.close();
        connection = undefined;
    }
    var config = new PeerConnectionConfig();
    config.open_data_channel = true;
    config.open_audio_channel = true;
    connect_peer(config).then(function (c) { return connection = c; }, function (error) {
        console.log("Got connect error %o", error);
    });
});
$("#disconnect").on('click', function (event) {
    if (connection) {
        connection.peer.close();
        connection.socket.close();
        connection = undefined;
    }
});
$("#send").on('click', function () {
    var message = $("#message").val().toString();
    console.log("Send message: %s", message);
    if (connection && connection.data_channels.length)
        connection.data_channels[0].send(message);
    else
        console.log("Missing channel!");
});
var PeerConnectionConfig = /** @class */ (function () {
    function PeerConnectionConfig() {
        this.open_data_channel = false;
        this.open_audio_channel = false;
    }
    return PeerConnectionConfig;
}());
var track;
var RemoteSource = /** @class */ (function () {
    function RemoteSource() {
    }
    return RemoteSource;
}());
var remote_sources = [];
var PeerConnection = /** @class */ (function () {
    function PeerConnection() {
        this.data_channels = [];
    }
    PeerConnection.prototype.initialized_peer = function () {
        var _this = this;
        var config = { /*iceServers: [{ url: 'stun:stun.l.google.com:19302' }]*/};
        this.peer = new RTCPeerConnection(config);
        this.peer.ontrack = function (event) {
            console.log("[RTC] Got new track %o (%o | %o) | %o", event.track.id, event.track.label, event.track, event.track.kind);
            event.track.onended = function (e) {
                console.log("[RTC] Track %o ended (%o)", event.track.id, e.error);
            };
            event.track.onmute = function (e) {
                console.log("[RTC] Track %o muted", event.track.id);
            };
            event.track.onunmute = function (e) {
                console.log("[RTC] Track %o unmuted", event.track.id);
            };
            event.track.onoverconstrained = function (e) {
                console.log("[RTC] Track %o onoverconstrained", event.track.id);
            };
        };
        this.peer.onnegotiationneeded = function (event) {
            console.log("NEGOT NEEDED!");
        };
        this.peer.onconnectionstatechange = function (event) {
            console.log("[RTC] Connection state change %o (%o)", event.eventPhase, event);
        };
        this.peer.onicecandidateerror = function (event) {
            console.log("[RTC][ICE] Failed to setup candidate %s (%s) (%o | %s)", event.hostCandidate, event.url, event.errorCode, event.errorText);
        };
        this.peer.oniceconnectionstatechange = function (event) {
            console.log("[RTC][ICE] Connection state change %o (%o)", event.eventPhase, event);
        };
        this.peer.onicegatheringstatechange = function (event) {
            console.log("[RTC][ICE] Gathering state change %o (%o)", event.eventPhase, event);
        };
        this.peer.onicecandidate = function (event) {
            console.log("[RTC][ICE][LOCAL] Got new candidate %s (%o)", event.candidate, event);
            if (event) {
                if (event.candidate)
                    _this.socket.send(JSON.stringify({
                        type: 'candidate',
                        msg: event.candidate
                    }));
                else
                    _this.socket.send(JSON.stringify({
                        type: 'candidate_finish'
                    }));
            }
        };
        this.peer.onaddstream = function (event) {
            console.log("[RTC] Got a new stream %o (%o)", event.stream.id, event);
            event.stream.onactive = function (e) {
                console.log("[RTC][STREAM] Stream %o got active", event.stream.id);
            };
            event.stream.oninactive = function (e) {
                console.log("[RTC][STREAM] Stream %o got inactive", event.stream.id);
            };
            event.stream.onaddtrack = function (e) {
                console.log("[RTC][STREAM] Stream %o got a new track %o", event.stream.id, e.track.id);
            };
            event.stream.onremovetrack = function (e) {
                console.log("[RTC][STREAM] Stream %o removed the track %o", event.stream.id, e.track.id);
            };
            var handle = new RemoteSource();
            handle.stream = event.stream;
            var context = audio_stream();
            handle.media_stream = context.createMediaStreamSource(event.stream);
            handle.script_prcessor = context.createScriptProcessor(1024, 2, 2);
            //handle.media_stream.connect(handle.script_prcessor);
            handle.script_prcessor.addEventListener('audioprocess', function (ev) {
                if (!disable_console) {
                    var buffer = ev.inputBuffer.getChannelData(0);
                    var sum = 0;
                    for (var _i = 0, buffer_1 = buffer; _i < buffer_1.length; _i++) {
                        var c = buffer_1[_i];
                        sum += c;
                    }
                    console.log("Got buffer sum of %o with length %o", sum, buffer.length);
                }
                for (var channel = 0; channel < ev.outputBuffer.numberOfChannels; channel++) {
                    ev.outputBuffer.copyToChannel(ev.inputBuffer.getChannelData(channel), channel);
                }
            });
            handle.script_prcessor.connect(context.destination);
            handle.audio = new Audio();
            try {
                handle.audio.srcObject = event.stream;
            }
            catch (_) {
                handle.audio.src = (URL || webkitURL || mozURL).createObjectURL(event.stream);
            }
            remote_sources.push(handle);
        };
        this.peer.onremovestream = function (event) {
            console.log("[RTC] Removed a stream %o (%o)", event.stream.id, event);
        };
        this.peer.ondatachannel = function (event) {
            console.log("[RTC] Got new channel (Label: %s Id: %o)", event.channel.label, event.channel.id);
            _this.initialize_data_channel(event.channel);
        };
        if (this.config.open_data_channel) {
            var dataChannel = this.peer.createDataChannel('main', { ordered: false, maxRetransmits: 0 });
            this.initialize_data_channel(dataChannel);
        }
        var sdpConstraints = {};
        sdpConstraints.offerToReceiveAudio = this.config.open_audio_channel;
        sdpConstraints.offerToReceiveVideo = false;
        navigator.mediaDevices.getUserMedia({ audio: true, video: false })
            .then(function (stream) {
            console.log("[GOT MIC!] %o", stream.getAudioTracks());
            if (_this.config.open_audio_channel) {
                _this.peer.addStream(stream);
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
            _this.peer.createOffer(function (sdp) {
                console.log("Got SDP: %s", sdp.sdp);
                _this.peer.setLocalDescription(sdp).then(function () {
                    console.log("[RTC] Got local sdp. Sending to partner");
                    _this.socket.send(JSON.stringify({
                        type: "offer",
                        msg: sdp
                    }));
                });
            }, function () {
                console.log("[RTC] Failed to setup peer!");
            }, sdpConstraints);
        })["catch"](function (err) {
            /* handle the error */
        });
        return true;
    };
    PeerConnection.prototype.initialize_data_channel = function (channel) {
        channel.onmessage = function (event) {
            console.log("[DC] Got new message on %s channel: %o", channel.label, event.data);
        };
        channel.onopen = function (event) {
            console.log("[DC] Channel %s opened!", channel.label);
        };
        channel.onclose = function (event) {
            console.log("[DC] Channel %s closed!", channel.label);
        };
        channel.onerror = function (event) {
            console.log("[DC] On channel %s occured an error: %o", channel.label, event);
        };
        this.data_channels.push(channel);
    };
    return PeerConnection;
}());
/*

 */
function connect_peer(config) {
    if (!config)
        config = new PeerConnectionConfig();
    return new Promise(function (resolve, reject) {
        var result = new PeerConnection();
        result.config = config;
        result.socket = new WebSocket("wss://192.168.43.141:1111");
        //result.socket = new WebSocket("wss://felix.did.science:1111");
        result.socket.onopen = function (event) {
            console.log("[WS] WebSocket connected!");
            result.initialized_peer();
            resolve(result);
        };
        result.socket.onclose = function (event) {
            console.log("[WS] WebSocket disconnected (%o)!", event.reason);
        };
        result.socket.onerror = function (event) {
            console.log("[WS] Got error %s!", event.type);
        };
        var candidate_buffer = [];
        var candidate_apply = function (candidate) {
            result.peer.addIceCandidate(candidate).then(function (any) {
                console.log("[RTC][ICE][REMOTE] Sucessfully setupped candidate %o", candidate);
            })["catch"](function (error) {
                console.log("[RTC][ICE][REMOTE] Failed to add candidate %o", error);
            });
        };
        result.socket.onmessage = function (event) {
            var data = JSON.parse(event.data);
            if (data["type"] == "candidate") {
                if (candidate_buffer) {
                    candidate_buffer.push(new RTCIceCandidate(data["msg"]));
                }
                else
                    candidate_apply(new RTCIceCandidate(data["msg"]));
            }
            else if (data["type"] == "answer") {
                console.log("[RTC][SDP] Setting remote answer!");
                result.peer.setRemoteDescription(new RTCSessionDescription(data["msg"])).then(function () {
                    console.log("[RTC][SDP] Remote answer set!");
                    for (var _i = 0, candidate_buffer_1 = candidate_buffer; _i < candidate_buffer_1.length; _i++) {
                        var can = candidate_buffer_1[_i];
                        candidate_apply(can);
                    }
                    candidate_buffer = undefined;
                })["catch"](function (error) {
                    console.log("Failed to set remote exception %o", error);
                });
            }
            else {
                console.log("Invalid message type %o", data["type"]);
            }
        };
    });
}
