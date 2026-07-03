package com.understory.aegis

import android.graphics.Color

/**
 * The IME is plain Android Views (no Compose), so it can't read the shared
 * [com.understory.security.ui.theme.UnderstoryTheme] token set directly. This
 * object mirrors the suite's dark token values as raw ARGB ints so the keyboard
 * matches the app instead of the old off-palette Holo indigo (design §2.3, §5.1).
 *
 * Values track the dark scheme in common-security's `ui/theme/Color.kt`
 * (surface/onSurface/onSurfaceVariant + the AEGIS accent seed as the primary
 * button fill). If those tokens change, update here in lockstep — a comment
 * because Views can't reach the CompositionLocal.
 */
object ImeColors {
    val surface: Int = Color.parseColor("#FF0B0B0B")
    val surfaceVariant: Int = Color.parseColor("#FF1E1E1E")
    val onSurface: Int = Color.parseColor("#FFE0E0E0")
    val onSurfaceVariant: Int = Color.parseColor("#FF9E9E9E")
    val warn: Int = Color.parseColor("#FFFFB74D")
    val error: Int = Color.parseColor("#FFEF5350")
    /** AEGIS accent seed (UnderstoryAccent.AEGIS) as the primary action fill. */
    val primary: Int = Color.parseColor("#FF8AA3C9")
    val onPrimary: Int = Color.parseColor("#FF0B0B0B")
}
