var __spreadArrays = (this && this.__spreadArrays) || function () {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};
var connection;
var button_connect = $("#connect");
var video_source = document.getElementById("video_input");
var video_source_stream;
var should_video_2 = false;
var video_target = document.getElementById("video_output");
var video_target2 = document.getElementById("video_output2");
/* setting up video target listener */
{
    for (var event_1 in video_target) {
        if (event_1.indexOf('on') != 0)
            continue;
        //video_target[event] = e => console.log("[VIDEO][OUT] Received event %s: %o", event, e);
    }
    video_target.oncanplaythrough = function () { return video_target.play(); };
}
if (false) {
    console.log = function () { };
    console.debug = function () { };
}
button_connect.on('click', function () {
    if (connection) {
        connection.peer.close();
        connection.socket.close();
        connection = undefined;
    }
    connect_peer().then(function (c) { return connection = c; }, function (error) {
        console.log("Got connect error %o", error);
    });
});
var PeerConnection = /** @class */ (function () {
    function PeerConnection() {
        this.data_channels = [];
    }
    PeerConnection.prototype.initialized_peer = function () {
        var _this = this;
        var config = {
            /*iceServers: [{ url: 'stun:stun.l.google.com:19302' }]*/
            sdpSemantics: "plan-b"
        };
        this.peer = new RTCPeerConnection(config);
        var _loop_1 = function (field) {
            if (field.indexOf('on') != 0)
                return "continue";
            //console.log('[RTC] Register event %s', field);
            this_1.peer[field] = function (event) { return console.log("[RTC] Event %s triggered: %o", field, event); };
        };
        var this_1 = this;
        for (var field in this.peer) {
            _loop_1(field);
        }
        this.peer.onsignalingstatechange = function () {
            console.log("[RTC] Signalling state changed to %s", _this.peer.signalingState);
        };
        this.peer.onconnectionstatechange = function () {
            console.log("[RTC] Connection state changed %s", _this.peer.connectionState);
        };
        this.peer.oniceconnectionstatechange = function () {
            console.log("[RTC][ICE] Connection state changed %s", _this.peer.iceConnectionState);
        };
        this.peer.onicegatheringstatechange = function () {
            console.log("[RTC][ICE] Ice gathering state changed %s", _this.peer.iceGatheringState);
        };
        this.peer.onicecandidateerror = function (event) {
            console.log("[RTC][ICE] Failed to setup candidate %s (%s) (%o | %s)", event.hostCandidate, event.url, event.errorCode, event.errorText);
        };
        this.peer.onicecandidate = function (event) {
            console.log("[RTC][ICE][LOCAL] Got new candidate %o", event.candidate);
            if (event.candidate)
                _this.socket.send(JSON.stringify({
                    type: 'candidate',
                    msg: event.candidate
                }));
            else
                _this.socket.send(JSON.stringify({
                    type: 'candidate_finish'
                }));
        };
        if (true) {
            this.peer.ontrack = function (event) {
                console.log("[RTC] Got new track %s (%s). Track: %o", event.track.label, event.track.kind, event.track);
                var stream = new MediaStream();
                stream.addTrack(event.track);
                video_target.srcObject = stream;
                event.track.onended = function (e) {
                    console.log("[RTC] Track %o ended", event.track.label);
                };
                event.track.onmute = function (e) {
                    console.log("[RTC] Track %o muted", event.track.id);
                };
                event.track.onunmute = function (e) {
                    console.log("[RTC] Track %o unmuted", event.track.id);
                };
                event.track.onisolationchange = function (e) {
                    console.log("[RTC] Track %o onisolationchange", event.track.id);
                };
            };
        }
        if (false) {
            this.peer.onaddstream = function (event) {
                console.log("[RTC] Got a new stream %o (%o)", event.stream.id, event);
                if (!should_video_2) {
                    video_target.srcObject = event.stream;
                    should_video_2 = !!video_target2;
                }
                else
                    video_target2.srcObject = event.stream;
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
                /* TODO pipe here something */
            };
            this.peer.onremovestream = function (event) {
                console.log("[RTC] Removed a stream %o (%o)", event.stream.id, event);
            };
        }
        this.peer.ondatachannel = function (event) {
            console.log("[RTC] Got new channel (Label: %s Id: %o)", event.channel.label, event.channel.id);
            _this.initialize_data_channel(event.channel);
        };
        var sdpConstraints = {};
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
            var media_stream = new MediaStream();
            ////this.peer.addStream(video_source_stream);
            //this.peer.addTrack(video_source.captureStream(0).getVideoTracks()[0], media_stream);
            //this.peer.addStream(video_source.captureStream(25));
        }
        this.peer.addStream(video_source_stream);
        console.log("[RTC] Generating offer");
        this.peer.createOffer(sdpConstraints).then(function (sdp) {
            {
                console.groupCollapsed("[RTC][SDP] Got local offer, applying offer and sending it to partner");
                console.log(sdp.sdp);
                console.groupEnd();
            }
            _this.peer.setLocalDescription(sdp).then(function () {
                console.log("[RTC][SDP] Offer applied, sending to partner");
                _this.socket.send(JSON.stringify({
                    type: "offer",
                    msg: sdp
                }));
            });
        })["catch"](function () {
            console.log("[RTC] Failed to setup peer!");
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
function connect_peer() {
    return new Promise(function (resolve, reject) {
        var result = new PeerConnection();
        result.socket = new WebSocket("wss://192.168.40.130:1111");
        should_video_2 = false;
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
                {
                    console.groupCollapsed("[RTC][SDP] Received remote offer, applying offer ");
                    console.log(data["msg"]["sdp"]);
                    console.groupEnd();
                }
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
/* draw stuff */
{
    var canvas_1 = video_source.getContext("2d");
    var canvas_width_1 = video_source.width;
    var canvas_height_1 = video_source.height;
    canvas_1.font = "20px sans-serif";
    var position_x_1 = canvas_width_1 / 2, position_y_1 = canvas_height_1 / 2;
    var motion_x_1 = 1, motion_y_1 = 1;
    var flag_motion_change_1 = false;
    var text_1 = "Hello World";
    var text_measurements_1 = {
        height: parseInt(canvas_1.font.match(/\d+/)[0], 10),
        width: canvas_1.measureText(text_1).width
    };
    var bg_color_chars_1 = "0123456789ABCDEF";
    var bg_color_1 = "#FFFFFF";
    console.log("Text measurement: %o. Front: %s", text_measurements_1, canvas_1.font);
    var update = function () {
        position_x_1 += motion_x_1;
        position_y_1 += motion_y_1;
        flag_motion_change_1 = false;
        if (position_x_1 < 0) {
            position_x_1 = 0;
            motion_x_1 *= -1;
            flag_motion_change_1 = true;
        }
        if (position_x_1 > canvas_width_1 - text_measurements_1.width) {
            position_x_1 = canvas_width_1 - text_measurements_1.width;
            motion_x_1 *= -1;
            flag_motion_change_1 = true;
        }
        if (position_y_1 < text_measurements_1.height) {
            position_y_1 = text_measurements_1.height;
            motion_y_1 *= -1;
            flag_motion_change_1 = true;
        }
        if (position_y_1 > canvas_height_1) {
            position_y_1 = canvas_height_1;
            motion_y_1 *= -1;
            flag_motion_change_1 = true;
        }
        if (flag_motion_change_1)
            bg_color_1 = '#' + __spreadArrays(new Array(6)).map(function () { return bg_color_chars_1.charAt(Math.floor(Math.random() * bg_color_chars_1.length)); }).reduce(function (a, b) { return a + b; });
        canvas_1.fillStyle = bg_color_1;
        canvas_1.fillRect(0, 0, canvas_width_1, canvas_height_1);
        canvas_1.strokeStyle = "#000000";
        canvas_1.strokeText(text_1, position_x_1, position_y_1);
    };
    setInterval(update, 25);
    update();
}
