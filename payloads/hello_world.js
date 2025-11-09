// Hello World Payload
// Clear existing logs and show large "Hello World" text

// Clear the logger lines
logger.lines = [];
logger.refresh();

// Create a large text widget
var helloWidget = nrdp.gibbon.makeWidget({
    name: "hello",
    x: 200,
    y: 250,
    width: 880,
    height: 220
});

helloWidget.text = {
    contents: "HELLO WORLD",
    size: 72,
    color: { a: 255, r: 0, g: 255, b: 255 }, // Cyan
    wrap: false
};

helloWidget.parent = logger.overlay;

// Send notification
send_notification("Hello Netflix! 🎬");

// Log success
logger.log("Payload executed!");
logger.log("Hello World displayed");
logger.flush();
