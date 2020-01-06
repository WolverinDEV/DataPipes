let connection;
let button_connect = $("#connect");
const video_source = document.getElementById("video_input");
let video_source_stream;
let should_video_2 = false;
const video_target = document.getElementById("video_output");
const video_target2 = document.getElementById("video_output2");
/* setting up video target listener */
{
    for (const event in video_target) {
        if (event.indexOf('on') != 0)
            continue;
        //video_target[event] = e => console.log("[VIDEO][OUT] Received event %s: %o", event, e);
    }
    video_target.oncanplaythrough = () => video_target.play();
}
if (false) {
    console.log = () => { };
    console.debug = () => { };
}
button_connect.on('click', () => {
    if (connection) {
        connection.peer.close();
        connection.socket.close();
        connection = undefined;
    }
    connect_peer().then(c => connection = c, error => {
        console.log("Got connect error %o", error);
    });
});
class PeerConnection {
    constructor() {
        this.data_channels = [];
    }
    initialized_peer() {
        const config = {
            /*iceServers: [{ url: 'stun:stun.l.google.com:19302' }]*/
            sdpSemantics: "plan-b"
        };
        this.peer = new RTCPeerConnection(config);
        for (const field in this.peer) {
            if (field.indexOf('on') != 0)
                continue;
            //console.log('[RTC] Register event %s', field);
            this.peer[field] = event => console.log("[RTC] Event %s triggered: %o", field, event);
        }
        this.peer.onsignalingstatechange = () => {
            console.log("[RTC] Signalling state changed to %s", this.peer.signalingState);
        };
        this.peer.onconnectionstatechange = () => {
            console.log("[RTC] Connection state changed %s", this.peer.connectionState);
        };
        this.peer.oniceconnectionstatechange = () => {
            console.log("[RTC][ICE] Connection state changed %s", this.peer.iceConnectionState);
        };
        this.peer.onicegatheringstatechange = () => {
            console.log("[RTC][ICE] Ice gathering state changed %s", this.peer.iceGatheringState);
        };
        this.peer.onicecandidateerror = event => {
            console.log("[RTC][ICE] Failed to setup candidate %s (%s) (%o | %s)", event.hostCandidate, event.url, event.errorCode, event.errorText);
        };
        this.peer.onicecandidate = (event) => {
            console.log("[RTC][ICE][LOCAL] Got new candidate %o", event.candidate);
            if (event.candidate)
                this.socket.send(JSON.stringify({
                    type: 'candidate',
                    msg: event.candidate
                }));
            else
                this.socket.send(JSON.stringify({
                    type: 'candidate_finish'
                }));
        };
        if (true) {
            this.peer.ontrack = event => {
                console.log("[RTC] Got new track %s (%s). Track: %o", event.track.label, event.track.kind, event.track);
                const stream = new MediaStream();
                stream.addTrack(event.track);
                video_target.srcObject = stream;
                event.track.onended = e => {
                    console.log("[RTC] Track %o ended", event.track.label);
                };
                event.track.onmute = e => {
                    console.log("[RTC] Track %o muted", event.track.id);
                };
                event.track.onunmute = e => {
                    console.log("[RTC] Track %o unmuted", event.track.id);
                };
                event.track.onisolationchange = e => {
                    console.log("[RTC] Track %o onisolationchange", event.track.id);
                };
            };
        }
        if (false) {
            this.peer.onaddstream = event => {
                console.log("[RTC] Got a new stream %o (%o)", event.stream.id, event);
                if (!should_video_2) {
                    video_target.srcObject = event.stream;
                    should_video_2 = !!video_target2;
                }
                else
                    video_target2.srcObject = event.stream;
                event.stream.onactive = e => {
                    console.log("[RTC][STREAM] Stream %o got active", event.stream.id);
                };
                event.stream.oninactive = e => {
                    console.log("[RTC][STREAM] Stream %o got inactive", event.stream.id);
                };
                event.stream.onaddtrack = e => {
                    console.log("[RTC][STREAM] Stream %o got a new track %o", event.stream.id, e.track.id);
                };
                event.stream.onremovetrack = e => {
                    console.log("[RTC][STREAM] Stream %o removed the track %o", event.stream.id, e.track.id);
                };
                /* TODO pipe here something */
            };
            this.peer.onremovestream = event => {
                console.log("[RTC] Removed a stream %o (%o)", event.stream.id, event);
            };
        }
        this.peer.ondatachannel = event => {
            console.log("[RTC] Got new channel (Label: %s Id: %o)", event.channel.label, event.channel.id);
            this.initialize_data_channel(event.channel);
        };
        let sdpConstraints = {};
        sdpConstraints.offerToReceiveVideo = true;
        sdpConstraints.offerToReceiveAudio = false;
        console.log("[RTC] Initializing stream");
        //this.peer.createDataChannel("test_channel");
        if (!video_source_stream) {
            if (!video_source.captureStream)
                alert('Missing required function: video_source.captureStream');
            video_source_stream = video_source.captureStream(25);
            console.log("Created source stream: %o", video_source_stream);
            //video_target.srcObject = video_source_stream;
            const media_stream = new MediaStream();
            ////this.peer.addStream(video_source_stream);
            //this.peer.addTrack(video_source.captureStream(0).getVideoTracks()[0], media_stream);
            //this.peer.addStream(video_source.captureStream(25));
        }
        this.peer.addStream(video_source_stream);
        console.log("[RTC] Generating offer");
        this.peer.createOffer(sdpConstraints).then(sdp => {
            {
                console.groupCollapsed("[RTC][SDP] Got local offer, applying offer and sending it to partner");
                console.log(sdp.sdp);
                console.groupEnd();
            }
            this.peer.setLocalDescription(sdp).then(() => {
                console.log("[RTC][SDP] Offer applied, sending to partner");
                this.socket.send(JSON.stringify({
                    type: "offer",
                    msg: sdp
                }));
            });
        }).catch(() => {
            console.log("[RTC] Failed to setup peer!");
        });
        return true;
    }
    initialize_data_channel(channel) {
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
function connect_peer() {
    return new Promise((resolve, reject) => {
        let result = new PeerConnection();
        result.socket = new WebSocket("wss://192.168.40.130:1111");
        should_video_2 = false;
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
            if (data["type"] == "candidate") {
                if (candidate_buffer) {
                    candidate_buffer.push(new RTCIceCandidate(data["msg"]));
                }
                else
                    candidate_apply(new RTCIceCandidate(data["msg"]));
            }
            else if (data["type"] == "answer") {
                {
                    console.groupCollapsed("[RTC][SDP] Received remote offer, applying offer ");
                    console.log(data["msg"]["sdp"]);
                    console.groupEnd();
                }
                result.peer.setRemoteDescription(new RTCSessionDescription(data["msg"])).then(() => {
                    console.log("[RTC][SDP] Remote answer set!");
                    for (let can of candidate_buffer)
                        candidate_apply(can);
                    candidate_buffer = undefined;
                }).catch(error => {
                    console.log("Failed to set remote exception %o", error);
                });
            }
            else {
                console.log("Invalid message type %o", data["type"]);
            }
        };
    });
}
/* draw stuff */
{
    const canvas = video_source.getContext("2d");
    const canvas_width = video_source.width;
    const canvas_height = video_source.height;
    canvas.font = "20px sans-serif";
    let position_x = canvas_width / 2, position_y = canvas_height / 2;
    let motion_x = 1, motion_y = 1;
    let flag_motion_change = false;
    const text = "Hello World";
    const text_measurements = {
        height: parseInt(canvas.font.match(/\d+/)[0], 10),
        width: canvas.measureText(text).width
    };
    let bg_color_chars = "0123456789ABCDEF";
    let bg_color = "#FFFFFF";
    console.log("Text measurement: %o. Front: %s", text_measurements, canvas.font);
    const update = () => {
        position_x += motion_x;
        position_y += motion_y;
        flag_motion_change = false;
        if (position_x < 0) {
            position_x = 0;
            motion_x *= -1;
            flag_motion_change = true;
        }
        if (position_x > canvas_width - text_measurements.width) {
            position_x = canvas_width - text_measurements.width;
            motion_x *= -1;
            flag_motion_change = true;
        }
        if (position_y < text_measurements.height) {
            position_y = text_measurements.height;
            motion_y *= -1;
            flag_motion_change = true;
        }
        if (position_y > canvas_height) {
            position_y = canvas_height;
            motion_y *= -1;
            flag_motion_change = true;
        }
        if (flag_motion_change)
            bg_color = '#' + [...new Array(6)].map(() => bg_color_chars.charAt(Math.floor(Math.random() * bg_color_chars.length))).reduce((a, b) => a + b);
        canvas.fillStyle = bg_color;
        canvas.fillRect(0, 0, canvas_width, canvas_height);
        canvas.strokeStyle = "#000000";
        canvas.strokeText(text, position_x, position_y);
    };
    setInterval(update, 25);
    update();
}
//# sourceMappingURL=main.js.map