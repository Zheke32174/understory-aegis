package com.understory.aegis

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.io.InputStream

/**
 * In-process QR decoder for the gallery-only enrollment flow.
 *
 * The user picks a screenshot of an `otpauth://` QR code from their
 * device's gallery via SAF (ACTION_GET_CONTENT with an image MIME
 * wildcard) — no CAMERA permission required. We read the bitmap, run
 * ZXing's decoder, and return the decoded string.
 *
 * If the picked image isn't a QR (or is too small / blurry / etc.),
 * decode returns null. Caller surfaces a "couldn't read QR" message.
 *
 * Why gallery-only:
 *   - No CAMERA permission to strip / justify.
 *   - No permanent live-capture pipeline that could be misused.
 *   - User has full agency over which images we get to look at —
 *     they pick exactly one, only when they explicitly want to.
 *   - The "common case" of moving from another authenticator already
 *     produces a QR-as-screenshot; we cover that path natively.
 */
object QrDecoder {

    /**
     * Read the image at [uri], decode any QR code in it, return the
     * raw decoded string. Returns null if no QR was found or the URI
     * couldn't be read.
     */
    fun decode(ctx: Context, uri: Uri): String? {
        val bitmap = readBitmap(ctx, uri) ?: return null
        try {
            return decodeBitmap(bitmap)
        } finally {
            bitmap.recycle()
        }
    }

    private fun readBitmap(ctx: Context, uri: Uri): Bitmap? {
        return runCatching {
            // Two-pass decode. First pass with inJustDecodeBounds=true
            // fetches dimensions only — no pixel allocation. We then pick
            // an inSampleSize so the longest edge fits within MAX_EDGE_PX,
            // and decode for real. Without this, a 50 MP screenshot would
            // allocate ~200 MB ARGB_8888 and OOM the unlock flow; modern
            // phones already produce 108 MP files.
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            ctx.contentResolver.openInputStream(uri).use { s ->
                s ?: return null
                BitmapFactory.decodeStream(s, null, bounds)
            }
            val maxEdge = maxOf(bounds.outWidth, bounds.outHeight)
            require(maxEdge > 0) { "image has no dimensions" }
            val sample = generateSequence(1) { it * 2 }
                .first { (maxEdge / it) <= MAX_EDGE_PX }
            val opts = BitmapFactory.Options().apply {
                inSampleSize = sample
                inMutable = false
            }
            ctx.contentResolver.openInputStream(uri).use { s ->
                s ?: return null
                BitmapFactory.decodeStream(s, null, opts)
            }
        }.getOrNull()
    }

    /**
     * Cap the longest decoded edge. QR codes survive heavy downsampling —
     * even a 25-module Version 2 QR is readable at 256 px wide. 2048 is
     * generous and keeps the worst-case allocation at ~16 MB.
     */
    private const val MAX_EDGE_PX = 2048

    private fun decodeBitmap(bitmap: Bitmap): String? {
        val width = bitmap.width
        val height = bitmap.height
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
        val source = RGBLuminanceSource(width, height, pixels)
        val binary = BinaryBitmap(HybridBinarizer(source))
        return runCatching {
            MultiFormatReader().decode(binary).text
        }.getOrNull()
    }
}
