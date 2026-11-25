package kittoku.mvc.fragment

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.MaterialAutoCompleteTextView
import kittoku.mvc.R
import kittoku.mvc.databinding.ItemLogEventBinding
import kittoku.mvc.control.DiagnosticEvent
import kittoku.mvc.control.DiagnosticLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

internal class LogFragment : Fragment(R.layout.fragment_logs) {
    private val handler = Handler(Looper.getMainLooper())
    private var query = ""
    private var levelIndex = 0
    private var refreshScheduled = false
    private var displayedSnapshot = emptyList<DiagnosticEvent>()
    private var adapter: EventAdapter? = null
    private val levels = listOf("", "DEBUG", "INFO", "WARN", "ERROR")
    private val refresh = Runnable {
        refreshScheduled = false
        if (view != null && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            refreshEvents()
        }
    }
    private val logListener: () -> Unit = {
        handler.post {
            if (view != null && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) && !refreshScheduled) {
                refreshScheduled = true
                handler.postDelayed(refresh, 250L)
            }
        }
    }
    private val exportDocument = registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri == null) return@registerForActivityResult
        val appContext = requireContext().applicationContext
        lifecycleScope.launch {
            val success = withContext(Dispatchers.IO) {
                runCatching { DiagnosticLog.export(appContext, uri) }.isSuccess
            }
            val message = if (success) R.string.ui_log_exported else R.string.ui_log_export_failed
            Toast.makeText(appContext, message, Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        query = savedInstanceState?.getString("logs_query").orEmpty()
        levelIndex = (savedInstanceState?.getInt("logs_level") ?: 0).coerceIn(levels.indices)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        adapter = EventAdapter()
        view.findViewById<RecyclerView>(R.id.logList).apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = this@LogFragment.adapter
            itemAnimator = null
        }
        view.findViewById<MaterialSwitch>(R.id.logCollect).apply {
            isChecked = DiagnosticLog.isCollectionEnabled()
            setOnCheckedChangeListener { _, enabled ->
                DiagnosticLog.setCollectionEnabled(enabled)
                refreshEvents()
            }
        }
        view.findViewById<EditText>(R.id.logSearch).apply {
            setText(query)
            doAfterTextChanged { query = it?.toString().orEmpty(); renderEvents() }
        }
        view.findViewById<MaterialAutoCompleteTextView>(R.id.logLevel).apply {
            val labels = levels.map { it.ifEmpty { getString(R.string.ui_log_all_levels) } }
            setSimpleItems(labels.toTypedArray())
            setText(labels[levelIndex], false)
            setOnItemClickListener { _, _, position, _ ->
                levelIndex = position
                renderEvents()
            }
        }
        view.findViewById<MaterialButton>(R.id.logExport).setOnClickListener {
            val date = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.ROOT).format(Date())
            exportDocument.launch("Unofficial-SoftEther-VPN_$date.log")
        }
        view.findViewById<MaterialButton>(R.id.logClear).setOnClickListener {
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.ui_log_clear_title)
                .setMessage(R.string.ui_log_clear_message)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.ui_log_clear) { _, _ ->
                    DiagnosticLog.clear()
                    refreshEvents()
                }.show()
        }
        refreshEvents()
    }

    override fun onStart() {
        super.onStart()
        DiagnosticLog.addListener(logListener)
        refreshEvents()
    }
    override fun onStop() {
        DiagnosticLog.removeListener(logListener)
        handler.removeCallbacksAndMessages(null)
        refreshScheduled = false
        super.onStop()
    }
    override fun onDestroyView() {
        view?.findViewById<RecyclerView>(R.id.logList)?.adapter = null
        adapter = null
        super.onDestroyView()
    }
    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("logs_query", query)
        outState.putInt("logs_level", levelIndex)
        super.onSaveInstanceState(outState)
    }

    private fun refreshEvents() {
        displayedSnapshot = DiagnosticLog.snapshot()
        renderEvents()
    }

    private fun renderEvents() {
        val root = view ?: return
        val selectedLevel = levels[levelIndex]
        val search = query.trim()
        val events = displayedSnapshot.filter { event ->
            (selectedLevel.isEmpty() || event.level.equals(selectedLevel, ignoreCase = true)) &&
                (search.isEmpty() || event.message.contains(search, ignoreCase = true) ||
                    event.tag.contains(search, ignoreCase = true) || event.sessionId.contains(search, ignoreCase = true))
        }
        val list = root.findViewById<RecyclerView>(R.id.logList)
        val manager = list.layoutManager as? LinearLayoutManager
        val followTail = (adapter?.itemCount ?: 0) == 0 ||
            (manager?.findLastVisibleItemPosition() ?: -1) >= (adapter?.itemCount ?: 0) - 3
        adapter?.submit(events)
        if (followTail && events.isNotEmpty()) list.scrollToPosition(events.lastIndex)
        val hasEvents = displayedSnapshot.isNotEmpty()
        root.findViewById<MaterialButton>(R.id.logExport).isEnabled = hasEvents
        root.findViewById<MaterialButton>(R.id.logClear).isEnabled = hasEvents
        root.findViewById<TextView>(R.id.logCount).text = getString(R.string.ui_log_count, events.size, displayedSnapshot.size)
        root.findViewById<TextView>(R.id.logEmpty).apply {
            visibility = if (events.isEmpty()) View.VISIBLE else View.GONE
            setText(when {
                hasEvents -> R.string.ui_log_no_match
                DiagnosticLog.isCollectionEnabled() -> R.string.ui_log_empty
                else -> R.string.ui_log_collection_off
            })
        }
    }

    private class EventAdapter : RecyclerView.Adapter<EventAdapter.Holder>() {
        private var events = emptyList<DiagnosticEvent>()
        private val dateFormat = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.getDefault())
        class Holder(val binding: ItemLogEventBinding) : RecyclerView.ViewHolder(binding.root)
        fun submit(value: List<DiagnosticEvent>) { events = value; notifyDataSetChanged() }
        override fun getItemCount() = events.size
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder =
            Holder(ItemLogEventBinding.inflate(LayoutInflater.from(parent.context), parent, false))
        override fun onBindViewHolder(holder: Holder, position: Int) {
            val event = events[position]
            holder.binding.eventHeader.text = "${dateFormat.format(Date(event.timestamp))}  ${event.level} · ${event.tag}" +
                if (event.sessionId.isBlank()) "" else "\n${event.sessionId}"
            val color = when (event.level.uppercase(Locale.ROOT)) {
                "ERROR" -> R.color.ui_error
                "WARN" -> R.color.ui_warning
                else -> R.color.ui_text_secondary
            }
            holder.binding.eventHeader.setTextColor(ContextCompat.getColor(holder.itemView.context, color))
            holder.binding.eventMessage.text = event.message
        }
    }
}
