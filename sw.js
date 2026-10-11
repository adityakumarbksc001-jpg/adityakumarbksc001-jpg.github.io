// Offline support for the portfolio. Keep this file next to index.html.
var C='folio-v1';
self.addEventListener('install',function(e){
  e.waitUntil(caches.open(C).then(function(c){return c.addAll(['./','index.html'])}).then(function(){return self.skipWaiting()}));
});
self.addEventListener('activate',function(e){
  e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==C}).map(function(k){return caches.delete(k)}))}).then(function(){return self.clients.claim()}));
});
self.addEventListener('fetch',function(e){
  var r=e.request;
  if(r.method!=='GET'||r.headers.has('range'))return;
  var u=new URL(r.url);
  if(u.origin!==location.origin||/\.(mp4|webm)$/i.test(u.pathname))return;   // only our own small files
  if(r.mode==='navigate'){
    // online: always the newest page (and keep a copy); offline: the saved copy
    e.respondWith(fetch(r).then(function(res){var cp=res.clone();caches.open(C).then(function(c){c.put(r,cp)});return res}).catch(function(){
      return caches.match(r).then(function(m){return m||caches.match('index.html')}).then(function(m){
        return m||new Response('<h1 style="font-family:sans-serif">You are offline</h1><p style="font-family:sans-serif">Reconnect and reload.</p>',{headers:{'Content-Type':'text/html'}});
      });
    }));
    return;
  }
  e.respondWith(caches.match(r).then(function(m){
    var net=fetch(r).then(function(res){if(res.ok){var cp=res.clone();caches.open(C).then(function(c){c.put(r,cp)})}return res}).catch(function(){return m});
    return m||net;
  }));
});
