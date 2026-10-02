const CACHE='stock-v1';
const ASSETS=['/','/static/index.html','/manifest.json','/about','/features','/help'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)));self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!=CACHE).map(k=>caches.delete(k)))))});
self.addEventListener('fetch',e=>{
  if(e.request.url.includes('/api/')||e.request.method!='GET'){e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));return}
  e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).then(res=>{const cp=res.clone();caches.open(CACHE).then(c=>c.put(e.request,cp));return res})));
});
