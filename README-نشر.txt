طريقة النشر على Netlify (الأكثر ضمانًا: عبر GitHub)
1) ارفع محتويات هذا المجلد إلى مستودع GitHub، ثم في Netlify: Add new site > Import from Git.
   Build command: اتركه فارغًا | Publish directory: .   (Netlify سيثبّت @netlify/blobs تلقائيًا)
2) Site configuration > Environment variables: أضف ADMIN_PASSWORD ثم أعد النشر (Deploys > Trigger deploy).
3) افتح موقعك ثم: المزيد > 🔐 الإدارة (أو الرابط /#/admin). ستظهر حالة الخدمة تحت حقل كلمة السر.
بديل: Netlify CLI:  npm i -g netlify-cli  ثم داخل المجلد:  npm install  ثم  netlify deploy --prod
