var GHPATH = '/JDasm';
var APP_PREFIX = 'jd_';
var VERSION = 'version_beta87';
var URLS = [    
  `${GHPATH}/`,
  `${GHPATH}/icon.png`,
  `${GHPATH}/manifest.json`,
  `${GHPATH}/index.html`,
  `${GHPATH}/RandomAccessFileV/FileReaderV.js`,
  `${GHPATH}/swingIO/UI.js`,
  `${GHPATH}/swingIO/Font/DOS.ttf`,
  `${GHPATH}/swingIO/Icons/f.gif`,
  `${GHPATH}/swingIO/Icons/u.gif`,
  `${GHPATH}/swingIO/Icons/H.gif`,
  `${GHPATH}/swingIO/Icons/disk.gif`,
  `${GHPATH}/swingIO/Icons/EXE.gif`,
  `${GHPATH}/swingIO/Icons/dll.gif`,
  `${GHPATH}/swingIO/Icons/sys.gif`,
  `${GHPATH}/swingIO/Icons/ELF.gif`,
  `${GHPATH}/swingIO/Icons/bmp.gif`,
  `${GHPATH}/swingIO/Icons/jpg.gif`,
  `${GHPATH}/swingIO/Icons/pal.gif`,
  `${GHPATH}/swingIO/Icons/ani.gif`,
  `${GHPATH}/swingIO/Icons/webp.gif`,
  `${GHPATH}/swingIO/Icons/wav.gif`,
  `${GHPATH}/swingIO/Icons/mid.gif`,
  `${GHPATH}/swingIO/Icons/avi.gif`,
  `${GHPATH}/core/x86/dis-x86.js`,
  `${GHPATH}/Format/com.js`,
  `${GHPATH}/Format/exe.js`,
  `${GHPATH}/Format/elf.js`,
  `${GHPATH}/Format/mac.js`,
  `${GHPATH}/Format/bmp.js`,
  `${GHPATH}/Format/jpeg.js`,
  `${GHPATH}/Format/riff.js`,
  `${GHPATH}/Format/zip.js`
]

var CACHE_NAME = APP_PREFIX + VERSION
self.addEventListener('fetch', function (e) {
  console.log('Fetch request : ' + e.request.url);
  e.respondWith(
    caches.match(e.request).then(function (request) {
      if (request) { 
        console.log('Responding with cache : ' + e.request.url);
        return request
      } else {       
        console.log('File is not cached, fetching : ' + e.request.url);
        return fetch(e.request)
      }
    })
  )
})

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      console.log('Installing cache : ' + CACHE_NAME);
      return cache.addAll(URLS)
    })
  )
})

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (keyList) {
      var cacheWhitelist = keyList.filter(function (key) {
        return key.indexOf(APP_PREFIX)
      })
      cacheWhitelist.push(CACHE_NAME);
      return Promise.all(keyList.map(function (key, i) {
        if (cacheWhitelist.indexOf(key) === -1) {
          console.log('Deleting cache : ' + keyList[i] );
          return caches.delete(keyList[i])
        }
      }))
    })
  )
})
