import logging
import asyncio
import ssl
import time
import io
import os
from dotenv import load_dotenv
import httpx
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)
from telegram.error import BadRequest

# --- توکن ربات خود را اینجا وارد کنید ---
#TELEGRAM_TOKEN = ""  # <--- !!! مهم: توکن خود را جایگزین کنید



# بارگذاری متغیرهای محیطی از فایل .env
load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
if not TELEGRAM_TOKEN:
    raise RuntimeError("TELEGRAM_TOKEN not found in environment. Please set TELEGRAM_TOKEN in .env")


logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)



def parse_line(line: str) -> tuple[str | None, str | None]:
    
    try:
        parts = line.strip().split(maxsplit=1)
        if len(parts) < 2:
            return None, None
        
        ip = parts[0]
        domain_list_str = parts[1]
        first_domain = domain_list_str.split(',')[0].strip()
        
        return ip, first_domain
    except Exception:
        return None, None

async def check_ping(ip: str) -> str:
    
    try:
        proc = await asyncio.create_subprocess_exec(
            'ping', '-c', '4', '-W', '2', ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode('utf-8')
            for line in output.splitlines():
                if 'rtt min/avg/max/mdev' in line or 'round-trip min/avg/max/stddev' in line:
                    avg_ping = line.split('/')[4]
                    return f"{float(avg_ping):.2f} ms"
            return "OK (No avg)"
        else:
            return "❌ Failed"
    except Exception:
        return "⚠️ Error"

async def check_tls_1_3(domain: str) -> str:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=context), timeout=5
        )
        sslsock = writer.get_extra_info('ssl_object')
        version = sslsock.version()
        writer.close()
        await writer.wait_closed()
        
        return "✅ Yes" if version == "TLSv1.3" else f"❌ No ({version})"
            
    except (ssl.SSLError, asyncio.TimeoutError, Exception):
        return "⚠️ Error/Timeout"

async def check_ttfb_and_validity(domain: str) -> tuple[str, str]:
    
    urls_to_try = [f"https://{domain}", f"http://{domain}"]
    parked_keywords = ["domain is parked", "domain for sale", "domain-geparkt", "website is parked", "fastdomain"]
    
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
        for url in urls_to_try:
            try:
                start_time = time.monotonic()
                try:
                    response = await client.head(url)
                    response.raise_for_status() 
                except httpx.HTTPStatusError:
                    response = await client.get(url)

                ttfb = time.monotonic() - start_time
                
                protocol = "HTTPS" if url.startswith("https") else "HTTP"
                ttfb_str = f"{ttfb:.2f}s ({protocol})"
                
                status = response.status_code
                content = response.text.lower() if response.text else ""
                
                is_parked = any(keyword in content for keyword in parked_keywords)
                
                if 200 <= status < 400:
                    if is_parked:
                        validity_str = f"⚠️ Parked ({status})"
                    else:
                        validity_str = f"✅ Real ({status})"
                else:
                    validity_str = f"❌ Error ({status})"
                    
                return ttfb_str, validity_str
                
            except httpx.RequestError:
                continue
                
    return "⚠️ Error", "❌ Unreachable"



async def process_lines_sequentially(lines_list: list[str], query: Update.callback_query) -> str:

    priority_results = []
    other_results = []
    
  
    header = f"{'IP 🖥️':<16} | {'Domain 🌐':<30} | {'Ping 📡':<12} | {'Speed ⚡':<15} | {'TLS 🔒':<15} | {'Validity 📊':<17}"
    separator = "-" * 110
    
    parsed_items = []
    all_lines_text = "\n".join(lines_list)
    for line in all_lines_text.splitlines():
        if not line.strip():
            continue
        ip, domain = parse_line(line)
        if not ip or not domain:
            continue
        parsed_items.append((ip, domain))

    total_count = len(parsed_items)
    if total_count == 0:
        return "No valid lines found to process."


    for i, (ip, domain) in enumerate(parsed_items):
        current_num = i + 1
        
        
        logger.info(f"[{current_num}/{total_count}] Processing {ip} - {domain}...")
        
       
        try:
            ping_res, tls_res, (ttfb_res, validity_res) = await asyncio.gather(
                check_ping(ip),
                check_tls_1_3(domain),
                check_ttfb_and_validity(domain)
            )
        except Exception as e:
            logger.error(f"Critical error processing {ip}: {e}")
            ping_res, tls_res, ttfb_res, validity_res = "Job Error", "Job Error", "Job Error", "Job Error"

       
        line_str = f"{ip:<16} | {domain:<30} | {ping_res:<12} | {ttfb_res:<15} | {tls_res:<15} | {validity_res:<17}"

      
        if tls_res == "✅ Yes":
            priority_results.append(line_str)
        else:
            other_results.append(line_str)

        # --- به‌روزرسانی وضعیت در ربات (هر 3 خط) ---
        if current_num % 3 == 0 or current_num == total_count:
            percent = (current_num / total_count) * 100
            
            progress_text = (
                f"⏳ **در حال پردازش...**\n\n"
                f"آیتم: {current_num} از {total_count}\n"
                f"پیشرفت: {percent:.0f}٪\n\n"
                f"*{domain}*... بررسی شد."
            )
            
            try:
                await query.edit_message_text(text=progress_text, parse_mode='Markdown')
            except BadRequest:
                pass 
            except Exception as e:
                logger.warning(f"Error editing message: {e}")

   
    final_output_lines = []
    final_output_lines.append(header)
    final_output_lines.append(separator)
    
    if priority_results:
        final_output_lines.append("\n--- 🌟 گزینه‌های پیشنهادی (TLS 1.3 فعال) 🌟 ---\n")
        final_output_lines.extend(priority_results)
    else:
        final_output_lines.append("\n--- ⚠️ هیچ گزینه‌ی مناسبی با TLS 1.3 یافت نشد ⚠️ ---\n")
        
    if other_results:
        final_output_lines.append("\n\n--- 🚫 گزینه‌های نامناسب (TLS 1.3 ندارند یا خطا) 🚫 ---\n")
        final_output_lines.extend(other_results)

    return "\n".join(final_output_lines)



async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """دستور /start را مدیریت می‌کند."""
    context.user_data['lines'] = []
    await update.message.reply_text(
        "🚀 **ربات بررسی‌کننده SNI خوش آمدید!** 🚀\n\n"
        "لطفاً لیست IP و دامنه‌های خود را ارسال کنید.\n"
        "فرمت هر خط: `IP_Address  domain1.com, ...`\n\n"
        "💡 می‌توانید لیست را در چند پیام جداگانه ارسال کنید.\n"
        "در پایان، دکمه «تأیید» را بزنید تا پردازش شروع شود."
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
   
    if 'lines' not in context.user_data:
        context.user_data['lines'] = []
        
    context.user_data['lines'].append(update.message.text)
    
    keyboard = [
        [InlineKeyboardButton("✅ تأیید و شروع بررسی", callback_data="start_processing")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        f"🗒️ پیام دریافت شد (مجموعاً {len(context.user_data['lines'])} پیام).\n"
        "می‌توانید باز هم ارسال کنید یا دکمه تأیید را بزنید.",
        reply_markup=reply_markup
    )



async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
   
    query = update.callback_query
    await query.answer()

    if query.data == "start_processing":
        lines_to_process = context.user_data.get('lines', [])
        
        if not lines_to_process:
        
            await query.edit_message_text(text="❌ لیستی برای پردازش وجود ندارد. لطفاً ابتدا لیست را ارسال کنید.")
            return

        
        try:
            
            chat_id = query.message.chat_id
        except Exception:
            logger.error("Could not retrieve chat_id safely.")
            
            await query.edit_message_text(text="❌ خطای بحرانی: امکان بازیابی شناسه چت وجود نداشت.")
            return

        context.user_data['lines'] = []
        
        await query.edit_message_text(text="✅ تأیید شد. در حال آماده‌سازی لیست...\n"
                                           "این فرآیند ممکن است کمی طول بکشد. لطفاً صبور باشید...")
        
        try:
            start_job_time = time.time()
            
            
            results_text = await process_lines_sequentially(lines_to_process, query)
            
            end_job_time = time.time()
            processing_time = end_job_time - start_job_time
            
            txt_buffer = io.BytesIO(results_text.encode('utf-8'))
            txt_buffer.name = "SNI_Check_Results.txt"
            
           
            try:
                await query.delete_message()
            except BadRequest as e:
           
                logger.warning(f"Failed to delete progress message: {e}")
            
            
            await context.bot.send_document(
                chat_id=chat_id,
                document=txt_buffer,
                caption=f"🏁 **پردازش کامل شد!** 🏁\n\n"
                        f"گزارش کامل در فایل `.txt` ضمیمه شد.\n"
                        f"کل زمان اجرا: {processing_time:.2f} ثانیه"
            )

        except Exception as e:
            logger.error(f"Error during processing job: {e}")
            
        
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"‼️ **خطای بحرانی** ‼️\n\n"
                     f"در هنگام پردازش خطایی رخ داد: {e}"
            )



def main() -> None:
    application = Application.builder().token(TELEGRAM_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(CallbackQueryHandler(button_callback))

    print("🚀 ربات (نسخه ۳) با موفقیت در حال اجرا است... (Ctrl+C برای توقف)")
    application.run_polling()

if __name__ == "__main__":
    main()
