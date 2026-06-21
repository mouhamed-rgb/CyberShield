// api/scan-url.js
// Endpoint: POST /api/scan-url
// يستقبل رابط، يبعثه لـ VirusTotal، ويرجع analysisId

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE_URL = "https://www.virustotal.com/api/v3";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  if (!VT_API_KEY) {
    console.error("VIRUSTOTAL_API_KEY is not set in environment variables");
    return res.status(500).json({ status: "error", message: "خطأ في إعدادات السيرفر" });
  }

  try {
    const { url } = req.body || {};

    if (!url || typeof url !== "string") {
      return res.status(400).json({
        status: "error",
        message: "الرجاء إرسال رابط صالح في الحقل 'url'.",
      });
    }

    // تحقق بسيط من صيغة الرابط
    try {
      new URL(url);
    } catch {
      return res.status(400).json({
        status: "error",
        message: "صيغة الرابط غير صحيحة.",
      });
    }

    // VirusTotal v3 يتطلب الرابط كـ form-urlencoded
    const body = new URLSearchParams();
    body.append("url", url);

    const vtResponse = await fetch(`${VT_BASE_URL}/urls`, {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });

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
    console.error("scan-url error:", err);
    return res.status(500).json({
      status: "error",
      message: "حدث خطأ غير متوقع في السيرفر.",
    });
  }
}
