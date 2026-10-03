const PAGES=[['/','📊 Dashboard'],['/items-page','📦 Items'],['/movements','🔄 Movements'],['/warehouses','🏬 Warehouses'],['/alerts','🚨 Alerts'],['/reports','📈 Reports'],['/suppliers','🏭 Suppliers'],['/purchases','🛒 Purchases'],['/sales-page','💰 Sales'],['/prices','💲 Prices'],['/users-page','👥 Users']];
function renderNav(){const t=localStorage.getItem('tok');const path=location.pathname;
 document.body.insertAdjacentHTML('afterbegin',`<nav><b>📦 StockManager</b>${PAGES.map(p=>`<a href="${p[0]}" class="${path==p[0]?'on':''}">${p[1]}</a>`).join('')}${t?'<a href="#" onclick="logout()">🚪 Logout</a>':''}</nav>`)}
function logout(){localStorage.clear();location.href='/'}
function tok(){return localStorage.getItem('tok')}
async function api(p,o={}){const r=await fetch(p,{...o,headers:{'Content-Type':'application/json','Authorization':'Bearer '+tok()}});if(r.status==401){logout();return null}return r.json()}
function guard(){if(!tok()&&!location.pathname.startsWith('/pages')){if(location.pathname!='/')location.href='/'}}
window.addEventListener('DOMContentLoaded',()=>{renderNav();guard()});
