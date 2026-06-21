// api/scan-file.js
// Endpoint: POST /api/scan-file
// يستقبل ملف من التطبيق، يبعثه لـ VirusTotal، ويرجع analysisId

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE_URL = "https://www.virustotal.com/api/v3";
const MAX_FILE_SIZE = 32 * 1024 * 1024; // 32MB

// Vercel: نعطل الـ body parser الافتراضي باش نقدر نتعامل مع multipart/form-data يدوياً
export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req, res) {
  // السماح فقط بـ POST
  if (req.method !== "POST") {
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  // التأكد من وجود API key فالسيرفر
  if (!VT_API_KEY) {
    console.error("VIRUSTOTAL_API_KEY is not set in environment variables");
    return res.status(500).json({ status: "error", message: "خطأ في إعدادات السيرفر" });
  }

  try {
    // قراءة الـ multipart/form-data يدوياً (formidable مكتبة خفيفة لهذا الغرض)
    const formidable = (await import("formidable")).default;
    const form = formidable({
      maxFileSize: MAX_FILE_SIZE,
      multiples: false,
    });

    const [fields, files] = await form.parse(req);

    const uploadedFile = files.file?.[0];
    if (!uploadedFile) {
      return res.status(400).json({
        status: "error",
        message: "لم يتم إرفاق أي ملف. تأكد من إرسال الحقل 'file'.",
      });
    }

    // التحقق من حجم الملف
    if (uploadedFile.size > MAX_FILE_SIZE) {
      return res.status(400).json({
        status: "error",
        message: "حجم الملف يتجاوز الحد الأقصى المسموح به (32MB).",
      });
    }

    // قراءة الملف وتجهيزه للإرسال إلى VirusTotal
    const fs = await import("fs");
    const fileBuffer = fs.readFileSync(uploadedFile.filepath);

    const vtFormData = new FormData();
    const blob = new Blob([fileBuffer]);
    vtFormData.append("file", blob, uploadedFile.originalFilename || "upload");

    const vtResponse = await fetch(`${VT_BASE_URL}/files`, {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
      },
      body: vtFormData,
    });

    // تنظيف الملف المؤقت
    fs.unlinkSync(uploadedFile.filepath);

    if (!vtResponse.ok) {
      const errorBody = await vtResponse.text();
      console.error("VirusTotal API error:", vtResponse.status, errorBody);

      if (vtResponse.status === 429) {
        return res.status(429).json({
          status: "error",
          message: "تم تجاوز الحد المسموح من الطلبات. حاول مرة أخرى بعد قليل.",
        });
      }

      return res.status(502).json({
        status: "error",
        message: "حدث خطأ أثناء التواصل مع خدمة الفحص.",
      });
    }

    const vtData = await vtResponse.json();
    const analysisId = vtData.data?.id;

    if (!analysisId) {
      return res.status(502).json({
        status: "error",
        message: "لم يتم استلام معرف تحليل صالح من خدمة الفحص.",
      });
    }

    return res.status(200).json({
      status: "queued",
      analysisId: analysisId,
    });
  } catch (err) {
    console.error("scan-file error:", err);

    // خطأ خاص بتجاوز حجم الملف من formidable
    if (err.code === "LIMIT_FILE_SIZE" || /maxFileSize/i.test(err.message || "")) {
      return res.status(400).json({
        status: "error",
        message: "حجم الملف يتجاوز الحد الأقصى المسموح به (32MB).",
      });
    }

    return res.status(500).json({
      status: "error",
      message: "حدث خطأ غير متوقع في السيرفر.",
    });
  }
}
