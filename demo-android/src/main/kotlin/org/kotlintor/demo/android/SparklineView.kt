package org.kotlintor.demo.android

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import com.google.android.material.color.MaterialColors

/** Minimal filled sparkline for profiler history series. */
class SparklineView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = resources.displayMetrics.density * 1.5f
        strokeJoin = Paint.Join.ROUND
        strokeCap = Paint.Cap.ROUND
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = resources.displayMetrics.density * 0.5f
    }
    private val path = Path()
    private val fillPath = Path()
    private var values: FloatArray = FloatArray(0)

    init {
        val primary = MaterialColors.getColor(this, com.google.android.material.R.attr.colorPrimary)
        val outline = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOutlineVariant)
        linePaint.color = primary
        fillPaint.color = (primary and 0x00FFFFFF) or 0x33000000
        gridPaint.color = outline
    }

    fun setValues(samples: List<Double>) {
        values = if (samples.isEmpty()) {
            FloatArray(0)
        } else {
            FloatArray(samples.size) { i -> samples[i].toFloat() }
        }
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0f || h <= 0f) return
        val pad = resources.displayMetrics.density * 4f
        canvas.drawLine(pad, h / 2f, w - pad, h / 2f, gridPaint)
        if (values.size < 2) return
        var min = values[0]
        var max = values[0]
        for (v in values) {
            if (v < min) min = v
            if (v > max) max = v
        }
        val span = (max - min).coerceAtLeast(1e-3f)
        path.reset()
        fillPath.reset()
        val usableW = w - pad * 2
        val usableH = h - pad * 2
        val last = (values.size - 1).coerceAtLeast(1)
        for (i in values.indices) {
            val x = pad + usableW * i / last
            val y = pad + usableH * (1f - (values[i] - min) / span)
            if (i == 0) {
                path.moveTo(x, y)
                fillPath.moveTo(x, h - pad)
                fillPath.lineTo(x, y)
            } else {
                path.lineTo(x, y)
                fillPath.lineTo(x, y)
            }
        }
        fillPath.lineTo(pad + usableW, h - pad)
        fillPath.close()
        canvas.drawPath(fillPath, fillPaint)
        canvas.drawPath(path, linePaint)
    }
}
