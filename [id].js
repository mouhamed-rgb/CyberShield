// api/result/[id].js
// Endpoint: GET /api/result/:analysisId
// يستعلم عن نتيجة التحليل من VirusTotal ويرجعها بشكل مبسط للتطبيق

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE_URL = "https://www.virustotal.com/api/v3";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  if (!VT_API_KEY) {
    console.error("VIRUSTOTAL_API_KEY is not set in environment variables");
    return res.status(500).json({ status: "error", message: "خطأ في إعدادات السيرفر" });
  }

  const { id } = req.query;

  if (!id || typeof id !== "string") {
    return res.status(400).json({
      status: "error",
      message: "معرف التحليل (analysisId) مفقود.",
    });
  }

  try {
    const vtResponse = await fetch(`${VT_BASE_URL}/analyses/${encodeURIComponent(id)}`, {
      method: "GET",
      headers: {
        "x-apikey": VT_API_KEY,
      },
    });

    if (!vtResponse.ok) {
      const errorBody = await vtResponse.text();
      console.error("VirusTotal API error:", vtResponse.status, errorBody);

      if (vtResponse.status === 404) {
        return res.status(404).json({
          status: "error",
          message: "لم يتم العثور على هذا التحليل.",
        });
      }

      if (vtResponse.status === 429) {
        return res.status(429).json({
          status: "error",
          message: "تم تجاوز الحد المسموح من الطلبات. حاول مرة أخرى بعد قليل.",
        });
      }

      return res.status(502).json({
        status: "error",
        message: "حدث خطأ أثناء جلب نتيجة الفحص.",
      });
    }

    const vtData = await vtResponse.json();
    const attributes = vtData.data?.attributes;
    const vtStatus = attributes?.status; // "queued" | "in-progress" | "completed"

    if (vtStatus === "completed") {
      const stats = attributes.stats || {};

      // محاولة استخراج permalink (موجود فقط لو كان للعنصر meta مرتبط بملف أو رابط)
      // VirusTotal لا يرجع permalink مباشرة في تحليل الـ analyses، نبنيه يدوياً
      const itemId = vtData.meta?.file_info?.sha256 || vtData.meta?.url_info?.id;
      let permalink = null;
      if (vtData.meta?.file_info?.sha256) {
        permalink = `https://www.virustotal.com/gui/file/${vtData.meta.file_info.sha256}`;
      } else if (vtData.meta?.url_info?.id) {
        permalink = `https://www.virustotal.com/gui/url/${vtData.meta.url_info.id}`;
      }

      return res.status(200).json({
        status: "completed",
        stats: {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0,
        },
        permalink: permalink,
      });
    }

    if (vtStatus === "queued" || vtStatus === "in-progress" || vtStatus === "pending") {
      return res.status(200).json({
        status: "pending",
      });
    }

    // أي حالة غير متوقعة
    return res.status(200).json({
      status: "pending",
    });
  } catch (err) {
    console.error("result error:", err);
    return res.status(500).json({
      status: "error",
      message: "حدث خطأ غير متوقع في السيرفر.",
    });
  }
}
