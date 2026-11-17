const menuButton=document.querySelector(".menu-toggle");
const nav=document.querySelector(".nav");
menuButton?.addEventListener("click",()=>{const open=nav.classList.toggle("open");menuButton.setAttribute("aria-expanded",String(open));});
nav?.querySelectorAll("a").forEach(a=>a.addEventListener("click",()=>{nav.classList.remove("open");menuButton?.setAttribute("aria-expanded","false");}));
document.getElementById("year").textContent=new Date().getFullYear();
const form=document.getElementById("contact-form");
form?.addEventListener("submit",async e=>{
 e.preventDefault();const status=form.querySelector(".form-status");const button=form.querySelector("button");
 button.disabled=true;status.textContent="Sending your enquiry…";
 try{const data=Object.fromEntries(new FormData(form).entries());const res=await fetch("/api/contact",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});const result=await res.json();if(!res.ok)throw new Error(result.error||"Unable to send enquiry.");form.reset();status.textContent=result.message||"Thank you. Your enquiry has been received.";}
 catch(err){status.textContent=err.message==="Failed to fetch"?"The enquiry service is not connected yet. Please try again later.":err.message;}
 finally{button.disabled=false;}
});