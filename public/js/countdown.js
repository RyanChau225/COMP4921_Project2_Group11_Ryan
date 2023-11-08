var seconds = document.getElementById('seconds-data').getAttribute('data-seconds');
var url = document.getElementById('url-data').getAttribute('data-url');

var interval = setInterval(function() {
    seconds--;
    document.getElementById('seconds').textContent = seconds;
    if (seconds === 0) {
        clearInterval(interval);
        window.location.href = url;
    }
}, 1000);
