const PAGES=[['/alerts','🚨 Alerts'],['/','📊 Dashboard'],['/items-page','📦 Items'],['/movements','🔄 Movements'],['/users-page','👥 Users'],['/warehouses','🏬 Warehouses'],['/prices','💲 Prices'],['/pos','🧾 Checkout'],['/suppliers','🏭 Suppliers'],['/purchases','🛒 Purchases'],['/sales-page','💰 Sales'],['/reports','📈 Reports']]
.sort((a,b)=>a[1].replace(/^\S+\s/,'').localeCompare(b[1].replace(/^\S+\s/,'')));
function renderNav(){const t=localStorage.getItem('tok');const path=location.pathname;
 document.body.insertAdjacentHTML('afterbegin',`<nav><b>📦 StockManager</b>${PAGES.map(p=>`<a href="${p[0]}" class="${path==p[0]?'on':''}">${p[1]}</a>`).join('')}${t?'<a href="#" onclick="logout()">🚪 Logout</a>':''}</nav>`)}
function logout(){localStorage.clear();location.href='/'}
function tok(){return localStorage.getItem('tok')}
async function api(p,o={}){const r=await fetch(p,{...o,headers:{'Content-Type':'application/json','Authorization':'Bearer '+tok()}});if(r.status==401){logout();return null}return r.json()}
function guard(){if(!tok()&&location.pathname!='/login')location.href='/login'}
window.addEventListener('DOMContentLoaded',()=>{renderNav();guard()});
