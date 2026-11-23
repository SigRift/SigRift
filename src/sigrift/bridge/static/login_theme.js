// Force a neutral theme on the unauthenticated login surface. The user's
// saved theme preference (incl. recreational themes like matrix) is
// re-applied post-auth by the dashboard. A ?theme=light query param is
// honored for accessibility; everything else falls back to dark.
(function(){
    var t = "dark";
    try {
        var q = new URLSearchParams(window.location.search).get("theme");
        if (q === "light") t = "light";
    } catch(_) {}
    document.documentElement.setAttribute("data-theme", t);
})();
