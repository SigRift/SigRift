/**
 * MLRF Gen4 Dashboard - Signal Browser
 * Taxonomy navigation (super-family > family > class), signal generation,
 * IQ constellation, PSD, DSP features, and compare mode.
 */
"use strict";

/* HTML-escape text (& < > " ') for element content and for quoted attribute
 * values. Not for unquoted attributes, URLs, inline handlers, script elements or style. */
function _sigEsc(s) {
    if (s == null) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/* -- SignalBrowser Class ---------------------------------------- */

function SignalBrowser(dashboard) {
    this.db = dashboard; this.superFamilies = []; this.classes = [];
    this.selSF = null; this.selFam = null; this.selCls = null;
    this.cmpCls = null; this.cmpMode = false;
    this._loadTaxonomy(); this._initControls();
}

SignalBrowser.prototype._loadTaxonomy = function() {
    var s = this;
    var sfEl = document.getElementById("sf-buttons");
    var ccEl = document.getElementById("class-cards");
    if (sfEl && typeof setLoadingState === "function") setLoadingState("sf-buttons", true);
    if (ccEl && typeof setLoadingState === "function") setLoadingState("class-cards", true);
    s.db.apiFetch("/api/signals/super-families").then(function(sf){
        s.superFamilies=sf; s._renderSF();
    }).catch(function(e){
        trackFetchError("signal-taxonomy", e);
        if (typeof setLoadingState === "function") setLoadingState("sf-buttons", false, "Failed to load taxonomy", "window.dashboard.signalBrowser._loadTaxonomy.bind(window.dashboard.signalBrowser)");
    });
    s.db.apiFetch("/api/signals/classes").then(function(c){
        s.classes=c; s._renderCards();
    }).catch(function(e){
        trackFetchError("signal-classes", e);
        if (typeof setLoadingState === "function") setLoadingState("class-cards", false, "Failed to load signal classes", "window.dashboard.signalBrowser._loadTaxonomy.bind(window.dashboard.signalBrowser)");
    });
};

/* -- Taxonomy UI ------------------------------------------------ */

SignalBrowser.prototype._renderSF = function() {
    var c = document.getElementById("sf-buttons"); if(!c) return;
    var s = this; c.innerHTML = "";
    var all = document.createElement("button");
    all.className = "tax-btn" + (s.selSF===null?" active":"");
    all.textContent = "All";
    all.addEventListener("click",function(){s.selSF=null;s.selFam=null;s._renderSF();});
    c.appendChild(all);
    for (var i=0;i<this.superFamilies.length;i++) {
        var sf=this.superFamilies[i], btn=document.createElement("button");
        btn.className="tax-btn"+(s.selSF===sf.super_family?" active":"");
        btn.textContent=sf.super_family; btn.setAttribute("data-sf",sf.super_family);
        btn.addEventListener("click",function(){s.selSF=this.getAttribute("data-sf");s.selFam=null;s._renderSF();});
        c.appendChild(btn);
    }
    this._renderFam(); this._renderCards();
};

SignalBrowser.prototype._renderFam = function() {
    var c=document.getElementById("family-list"); if(!c)return; c.innerHTML="";
    if(this.selSF===null) return;
    var sf=this.superFamilies.find(function(x){return x.super_family===this.selSF;}.bind(this));
    if(!sf||!sf.families)return;
    var s=this;
    for(var i=0;i<sf.families.length;i++){
        var f=sf.families[i], btn=document.createElement("button");
        btn.className="tax-btn"+(s.selFam===f?" active":"");
        btn.textContent=f; btn.setAttribute("data-fam",f);
        btn.addEventListener("click",function(){s.selFam=this.getAttribute("data-fam");s._renderFam();s._renderCards();});
        c.appendChild(btn);
    }
};

SignalBrowser.prototype._renderCards = function() {
    var c=document.getElementById("class-cards"); if(!c)return; c.innerHTML="";
    var f=this.classes, s=this;
    if(this.selSF) f=f.filter(function(x){return x.super_family===s.selSF;});
    if(this.selFam) f=f.filter(function(x){return x.family===s.selFam;});
    for(var i=0;i<f.length;i++){
        var cls=f[i], card=document.createElement("div");
        card.className="class-card"+(s.selCls===cls.name?" selected":"");
        card.textContent=cls.name; card.setAttribute("data-class",cls.name);
        card.addEventListener("click",function(){
            var cn=this.getAttribute("data-class");
            if(s.cmpMode){s.cmpCls=cn;s.cmpMode=false;s._doCompare();}
            else{s.selCls=cn;s._renderCards();s._showViewer(cn);}
        });
        c.appendChild(card);
    }
};

/* -- Signal Viewer ---------------------------------------------- */

SignalBrowser.prototype._initControls = function() {
    var s=this;
    var gen=document.getElementById("sig-generate"), cmp=document.getElementById("sig-compare");
    if(gen) gen.addEventListener("click",function(){if(s.selCls)s._generate(s.selCls);});
    if(cmp) cmp.addEventListener("click",function(){s.cmpMode=true;cmp.textContent="Select 2nd class...";});
};

SignalBrowser.prototype._showViewer = function(cls) {
    var v=document.getElementById("signal-viewer"); if(v)v.style.display="";
    var n=document.getElementById("sig-class-name"); if(n)n.textContent=cls;
    this._generate(cls);
};

SignalBrowser.prototype._generate = function(cls) {
    var s=this, snr=parseFloat((document.getElementById("sig-snr")||{value:15}).value);
    s.db.apiFetch("/api/signals/generate?class="+encodeURIComponent(cls)+"&snr="+snr)
        .then(function(d){s._drawConst(d.constellation_x,d.constellation_y);s._drawPSD(d.psd_db,d.psd_freq_hz);s._drawFeat(d.dsp_features);})
        .catch(function(){});
};

/* -- Canvas Helpers --------------------------------------------- */

function _clearCanvas(id) {
    var cv=document.getElementById(id); if(!cv) return null;
    var ctx=cv.getContext("2d"); ctx.fillStyle="#0d1117"; ctx.fillRect(0,0,cv.width,cv.height);
    return {ctx:ctx, w:cv.width, h:cv.height, p:30};
}
function _findRange(arr) {
    var mn=arr[0],mx=arr[0]; for(var i=1;i<arr.length;i++){if(arr[i]<mn)mn=arr[i];if(arr[i]>mx)mx=arr[i];}
    if(mx===mn)mx=mn+1; return{min:mn,max:mx};
}
function _maxAbs2D(cx,cy) {
    var m=0; for(var i=0;i<cx.length;i++){var a=Math.max(Math.abs(cx[i]),Math.abs(cy[i]));if(a>m)m=a;}
    return m===0?1:m*1.2;
}
function _drawGrid(ctx,w,h,p) {
    ctx.strokeStyle="#30363d"; ctx.lineWidth=0.5;
    ctx.beginPath(); ctx.moveTo(p,h/2); ctx.lineTo(w-p,h/2); ctx.moveTo(w/2,p); ctx.lineTo(w/2,h-p); ctx.stroke();
}
function _drawPts(ctx,cx,cy,maxA,w,h,p,color) {
    ctx.fillStyle=color;
    for(var j=0;j<cx.length;j++){var px=w/2+(cx[j]/maxA)*(w/2-p),py=h/2-(cy[j]/maxA)*(h/2-p);ctx.beginPath();ctx.arc(px,py,1.5,0,2*Math.PI);ctx.fill();}
}

/* -- Constellation ---------------------------------------------- */

SignalBrowser.prototype._drawConst = function(cx,cy) {
    var c=_clearCanvas("constellation-canvas"); if(!c||!cx||!cx.length) return;
    var ma=_maxAbs2D(cx,cy);
    _drawGrid(c.ctx,c.w,c.h,c.p);
    c.ctx.beginPath(); c.ctx.strokeStyle="#30363d";
    c.ctx.arc(c.w/2,c.h/2,((c.w-2*c.p)/2)*(1/ma),0,2*Math.PI); c.ctx.stroke();
    _drawPts(c.ctx,cx,cy,ma,c.w,c.h,c.p,"rgba(88,166,255,0.6)");
    c.ctx.fillStyle="#8b949e"; c.ctx.font="10px monospace"; c.ctx.textAlign="center";
    c.ctx.fillText("I",c.w-12,c.h/2-6); c.ctx.fillText("Q",c.w/2+10,c.p-6);
};

/* -- PSD -------------------------------------------------------- */

SignalBrowser.prototype._drawPSD = function(psd,freqs) {
    var c=_clearCanvas("psd-canvas"); if(!c||!psd||!psd.length)return;
    var r=_findRange(psd), n=psd.length;
    c.ctx.strokeStyle="#30363d"; c.ctx.lineWidth=0.5;
    for(var g=1;g<4;g++){var gy=c.p+(c.h-2*c.p)*g/4;c.ctx.beginPath();c.ctx.moveTo(c.p,gy);c.ctx.lineTo(c.w-c.p,gy);c.ctx.stroke();}
    c.ctx.beginPath(); c.ctx.strokeStyle="#3fb950"; c.ctx.lineWidth=1.5;
    for(var j=0;j<n;j++){
        var x=c.p+(j/n)*(c.w-2*c.p), y=c.p+(1-(psd[j]-r.min)/(r.max-r.min))*(c.h-2*c.p);
        j===0?c.ctx.moveTo(x,y):c.ctx.lineTo(x,y);
    }
    c.ctx.stroke();
    c.ctx.fillStyle="#8b949e"; c.ctx.font="10px monospace";
    c.ctx.textAlign="left"; c.ctx.fillText(r.max.toFixed(0)+" dB",2,c.p+10); c.ctx.fillText(r.min.toFixed(0)+" dB",2,c.h-c.p);
    c.ctx.textAlign="center"; c.ctx.fillText("Frequency (normalized)",c.w/2,c.h-4);
};

/* -- DSP Features ----------------------------------------------- */

var _FEAT_LABELS = ["N2pk","N4pk","N8pk","CP64","CP256","CP512","CP1K","CP2K","|C20|","aC20","|C40|","aC40","|C41|","C42","rC40","rC41"];
var _FEAT_COLORS = ["#58a6ff","#58a6ff","#58a6ff","#a371f7","#a371f7","#a371f7","#a371f7","#a371f7"];

SignalBrowser.prototype._drawFeat = function(feat) {
    var c=_clearCanvas("features-canvas"); if(!c||!feat||!feat.length)return;
    var n=feat.length, mx=0;
    for(var i=0;i<n;i++){var a=Math.abs(feat[i]);if(a>mx)mx=a;} if(mx===0)mx=1;
    var sp=(c.w-2*c.p)/n, bw=Math.max(4,sp-2);
    for(var j=0;j<n;j++){
        var bh=(Math.abs(feat[j])/mx)*(c.h-2*c.p), x=c.p+j*sp;
        c.ctx.fillStyle=j<3?"#58a6ff":j<8?"#a371f7":"#d29922";
        c.ctx.fillRect(x,c.h-c.p-bh,bw,bh);
        c.ctx.fillStyle="#8b949e"; c.ctx.font="8px monospace"; c.ctx.textAlign="center";
        c.ctx.fillText(j<_FEAT_LABELS.length?_FEAT_LABELS[j]:"F"+j, x+bw/2, c.h-c.p+12);
    }
    c.ctx.fillStyle="#8b949e"; c.ctx.font="10px monospace"; c.ctx.textAlign="left";
    c.ctx.fillText(mx.toFixed(2),2,c.p+10); c.ctx.fillText("0",2,c.h-c.p);
};

/* -- Compare Mode ----------------------------------------------- */

SignalBrowser.prototype._doCompare = function() {
    var s=this; if(!s.selCls||!s.cmpCls) return;
    s.db.apiFetch("/api/signals/compare",{method:"POST",body:[s.selCls,s.cmpCls],headers:{"Content-Type":"application/json"}})
        .then(function(r){if(r.length>=2){s._cmpConst(r[0],r[1]);s._cmpPSD(r[0],r[1]);s._cmpFeat(r[0],r[1]);}}).catch(function(){});
    var cb=document.getElementById("sig-compare"); if(cb)cb.textContent="Compare";
};

SignalBrowser.prototype._cmpConst = function(s1,s2) {
    var c=_clearCanvas("constellation-canvas"); if(!c) return;
    var ax=(s1.constellation_x||[]).concat(s2.constellation_x||[]), ay=(s1.constellation_y||[]).concat(s2.constellation_y||[]);
    var ma=_maxAbs2D(ax,ay); _drawGrid(c.ctx,c.w,c.h,c.p);
    _drawPts(c.ctx,s1.constellation_x||[],s1.constellation_y||[],ma,c.w,c.h,c.p,"rgba(88,166,255,0.5)");
    _drawPts(c.ctx,s2.constellation_x||[],s2.constellation_y||[],ma,c.w,c.h,c.p,"rgba(248,81,73,0.5)");
    c.ctx.font="10px sans-serif";
    c.ctx.fillStyle="#58a6ff";c.ctx.fillText(_sigEsc(s1.signal_class),c.p,c.p-6);
    c.ctx.fillStyle="#f85149";c.ctx.fillText(_sigEsc(s2.signal_class),c.p+80,c.p-6);
};

SignalBrowser.prototype._cmpPSD = function(s1,s2) {
    var c=_clearCanvas("psd-canvas"); if(!c) return;
    function drawL(psd,color){
        if(!psd||!psd.length)return; var r=_findRange(psd);
        c.ctx.beginPath();c.ctx.strokeStyle=color;c.ctx.lineWidth=1.5;
        for(var j=0;j<psd.length;j++){var x=c.p+(j/psd.length)*(c.w-2*c.p),y=c.p+(1-(psd[j]-r.min)/(r.max-r.min))*(c.h-2*c.p);j===0?c.ctx.moveTo(x,y):c.ctx.lineTo(x,y);}
        c.ctx.stroke();
    }
    drawL(s1.psd_db,"#3fb950"); drawL(s2.psd_db,"#f85149");
    c.ctx.font="10px sans-serif";
    c.ctx.fillStyle="#3fb950";c.ctx.fillText(_sigEsc(s1.signal_class),c.p,c.p-6);
    c.ctx.fillStyle="#f85149";c.ctx.fillText(_sigEsc(s2.signal_class),c.p+80,c.p-6);
};

SignalBrowser.prototype._cmpFeat = function(s1,s2) {
    var c=_clearCanvas("features-canvas"); if(!c)return;
    var f1=s1.dsp_features||[], f2=s2.dsp_features||[], n=Math.max(f1.length,f2.length);
    if(!n)return; var mx=0;
    for(var i=0;i<n;i++){if(i<f1.length&&Math.abs(f1[i])>mx)mx=Math.abs(f1[i]);if(i<f2.length&&Math.abs(f2[i])>mx)mx=Math.abs(f2[i]);}
    if(mx===0)mx=1; var sp=(c.w-2*c.p)/n, bw=Math.max(2,sp/2-1);
    for(var j=0;j<n;j++){
        var x=c.p+j*sp;
        if(j<f1.length){c.ctx.fillStyle="rgba(88,166,255,0.7)";var h1=(Math.abs(f1[j])/mx)*(c.h-2*c.p);c.ctx.fillRect(x,c.h-c.p-h1,bw,h1);}
        if(j<f2.length){c.ctx.fillStyle="rgba(248,81,73,0.7)";var h2=(Math.abs(f2[j])/mx)*(c.h-2*c.p);c.ctx.fillRect(x+bw+1,c.h-c.p-h2,bw,h2);}
    }
    c.ctx.font="10px sans-serif";
    c.ctx.fillStyle="#58a6ff";c.ctx.fillText(_sigEsc(s1.signal_class),c.p,c.p-6);
    c.ctx.fillStyle="#f85149";c.ctx.fillText(_sigEsc(s2.signal_class),c.p+80,c.p-6);
};
