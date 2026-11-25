package kittoku.mvc.activity

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import kittoku.mvc.routing.root.RootPackageSnapshot
import android.content.res.Configuration
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.text.Editable
import android.text.TextWatcher
import android.util.LruCache
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.PopupMenu
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.lifecycle.Lifecycle
import androidx.preference.PreferenceManager
import androidx.recyclerview.widget.ConcatAdapter
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kittoku.mvc.R
import kittoku.mvc.databinding.ActivityAppRoutingBinding
import kittoku.mvc.databinding.ItemAppRoutingControlsBinding
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.privacy.PrivacyDisclosure
import kittoku.mvc.routing.AppRoutingConfiguration
import kittoku.mvc.routing.AppRoutingMode
import kittoku.mvc.routing.AppRoutingPolicy
import kittoku.mvc.routing.AppRoutingSettings
import kittoku.mvc.ui.configureRoutingToolbar
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.ConcurrentHashMap

/** UI edits only app-local configuration. A reconnect applies the selected backend's policy. */
class AppRoutingActivity : AppCompatActivity() {
    private lateinit var binding: ActivityAppRoutingBinding
    private lateinit var controls: ItemAppRoutingControlsBinding
    private val routing by lazy { AppRoutingSettings(this) }
    private val defaults by lazy { PreferenceManager.getDefaultSharedPreferences(this) }
    private val main = Handler(Looper.getMainLooper())
    private val loader = Executors.newSingleThreadExecutor { task -> Thread(task, "home-vpn-app-list").also { it.isDaemon = true } }
    private val icons = Executors.newFixedThreadPool(2) { task -> Thread(task, "home-vpn-app-icon").also { it.isDaemon = true } }
    private val iconCache = LruCache<String, Drawable>(48)
    private val pendingIcons = ConcurrentHashMap.newKeySet<String>()
    private val ownUid = Process.myUid()
    private var configuration = AppRoutingConfiguration(AppRoutingMode.ALL, emptySet())
    private var entries: List<AppEntry> = emptyList()
    private var loading = false
    private var loadGeneration = 0
    private var rootBackend = true
    private lateinit var adapter: AppAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportFragmentManager.setFragmentResultListener(PrivacyDisclosureDialog.RESULT, this) { _, result ->
            if (!result.getBoolean(PrivacyDisclosureDialog.ACCEPTED)) finish()
            else if (lifecycle.currentState == Lifecycle.State.RESUMED) loadApplications()
        }
        WindowCompat.setDecorFitsSystemWindows(window, false)
        binding = ActivityAppRoutingBinding.inflate(layoutInflater)
        setContentView(binding.root)
        val night = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        WindowInsetsControllerCompat(window, binding.root).apply {
            isAppearanceLightStatusBars = !night; isAppearanceLightNavigationBars = !night
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            val keyboard = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.setPadding(bars.left, bars.top, bars.right, maxOf(bars.bottom, keyboard.bottom))
            WindowInsetsCompat.CONSUMED
        }
        ViewCompat.requestApplyInsets(binding.root)
        binding.pageHeading.pageToolbar.configureRoutingToolbar(
            R.string.app_routing_title, R.string.app_routing_help_message
        ) { finish() }
        adapter = AppAdapter()
        binding.appRoutingList.layoutManager = LinearLayoutManager(this)
        controls = ItemAppRoutingControlsBinding.inflate(layoutInflater, binding.appRoutingList, false)
        controls.appRoutingSearch.setText(savedInstanceState?.getString(STATE_SEARCH_QUERY))
        controls.appRoutingMore.setOnClickListener(::showAppActions)
        binding.appRoutingList.adapter = ConcatAdapter(AppRoutingControlsAdapter(controls.root), adapter)
        controls.appRoutingMode.isSaveFromParentEnabled = false
        controls.appRoutingMode.addOnButtonCheckedListener { _, checkedId, checked ->
            if (!checked) return@addOnButtonCheckedListener
            val mode = when (checkedId) {
                R.id.appRoutingModeBlacklist -> AppRoutingMode.EXCLUDE
                R.id.appRoutingModeWhitelist -> AppRoutingMode.INCLUDE
                R.id.appRoutingModeAll -> AppRoutingMode.ALL
                else -> return@addOnButtonCheckedListener
            }
            if (mode != configuration.mode) {
                configuration = configuration.copy(mode = mode)
                persistAndRender()
            }
        }
        controls.appRoutingShowSystem.isChecked = routing.showSystemApps()
        controls.appRoutingShowSystem.setOnCheckedChangeListener { _, checked ->
            routing.setShowSystemApps(checked); render()
        }
        controls.appRoutingSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { render() }
            override fun afterTextChanged(s: Editable?) {}
        })
    }

    private fun showAppActions(anchor: View) {
        PopupMenu(this, anchor, Gravity.END).apply {
            menu.add(R.string.app_routing_refresh).setOnMenuItemClickListener {
                loadApplications()
                true
            }
            menu.add(R.string.app_routing_clear).setOnMenuItemClickListener {
                configuration = configuration.copy(packages = emptySet())
                persistAndRender()
                true
            }
        }.show()
    }

    override fun onResume() {
        super.onResume()
        if (isFinishing) return
        configuration = runCatching { routing.load() }.getOrElse { error ->
            Toast.makeText(this, error.message, Toast.LENGTH_LONG).show()
            AppRoutingConfiguration(AppRoutingMode.ALL, emptySet())
        }
        rootBackend = getStringPrefValue(MvcPreference.BACKEND_MODE, defaults) != "TUN"
        loadApplications()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_SEARCH_QUERY, controls.appRoutingSearch.text?.toString())
    }

    private fun loadApplications() {
        if (!PrivacyDisclosure.APP_INVENTORY.accepted(this)) {
            PrivacyDisclosureDialog.show(supportFragmentManager, PrivacyDisclosure.APP_INVENTORY)
            return
        }
        val generation = ++loadGeneration
        val useRootSnapshot = rootBackend
        loading = true; render()
        loader.execute {
            val loaded = runCatching {
                val visible = packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0)).associateBy { it.packageName }
                fun visibleEntry(info: ApplicationInfo) =
                    AppEntry(info.packageName, runCatching { info.loadLabel(packageManager).toString() }
                        .getOrDefault(info.packageName), info.uid,
                        info.flags and ApplicationInfo.FLAG_SYSTEM != 0, info)
                val rows = if (useRootSnapshot) {
                    RootPackageSnapshot.load(this).map { root ->
                        val info = visible[root.packageName] ?: runCatching {
                            packageManager.getApplicationInfo(root.packageName, PackageManager.ApplicationInfoFlags.of(0))
                        }.getOrNull()
                        if (info != null) visibleEntry(info).copy(uid = root.uid, system = root.systemApp)
                        else AppEntry(root.packageName, root.packageName, root.uid, root.systemApp, null)
                    }
                } else visible.values.map(::visibleEntry)
                rows.sortedWith(compareBy<AppEntry> { it.label.lowercase(Locale.ROOT) }.thenBy { it.packageName })
            }
            main.post {
                if (isDestroyed || isFinishing || generation != loadGeneration) return@post
                loading = false
                loaded.onSuccess { result ->
                    entries = result
                    val ownerPackages = result.filter { it.uid == ownUid }.map { it.packageName }.toSet()
                    if (configuration.packages.any { it in ownerPackages }) {
                        configuration = configuration.copy(packages = configuration.packages - ownerPackages)
                        routing.save(configuration)
                    }
                }.onFailure { error ->
                    Toast.makeText(this, getString(R.string.app_routing_load_error, error.message.orEmpty()), Toast.LENGTH_LONG).show()
                }
                render()
            }
        }
    }

    private fun installedMap() = entries.mapNotNull { entry -> entry.uid?.let { entry.packageName to it } }.toMap()
    private fun selectedInstalled() = AppRoutingPolicy.selectedUidPackages(configuration.packages, installedMap(), ownUid)

    private fun isSelected(entry: AppEntry): Boolean {
        if (entry.packageName in configuration.packages) return true
        return entry.uid != null && entries.any { candidate ->
            candidate.uid == entry.uid && candidate.packageName in configuration.packages
        }
    }

    private fun render() {
        if (!::binding.isInitialized || !::adapter.isInitialized || isDestroyed) return
        val installed = installedMap()
        val selected = selectedInstalled()
        val missing = configuration.packages - installed.keys - packageName
        val query = controls.appRoutingSearch.text?.toString().orEmpty().trim()
        val orphanRows = missing.map { pkg -> AppEntry(pkg, getString(R.string.app_routing_not_installed), null, false, null) }
        val rows = (if (loading && entries.isEmpty()) emptyList() else entries + orphanRows).filter { entry ->
            entry.uid != ownUid && (controls.appRoutingShowSystem.isChecked || !entry.system || isSelected(entry)) &&
                (query.isEmpty() || entry.label.contains(query, ignoreCase = true) || entry.packageName.contains(query, ignoreCase = true))
        }
        adapter.replaceRows(rows)
        val (modeButton, modeHint) = when (configuration.mode) {
            AppRoutingMode.EXCLUDE -> R.id.appRoutingModeBlacklist to R.string.app_routing_black_hint
            AppRoutingMode.INCLUDE -> R.id.appRoutingModeWhitelist to
                if (selected.isEmpty() && !loading) R.string.app_routing_white_empty else R.string.app_routing_white_hint
            AppRoutingMode.ALL -> R.id.appRoutingModeAll to R.string.app_routing_all_hint
        }
        controls.appRoutingMode.check(modeButton)
        controls.appRoutingModeHint.setText(modeHint)
        controls.appRoutingCount.text = if (loading) getString(R.string.app_routing_loading)
        else getString(R.string.app_routing_selected_count, selected.size + missing.size, missing.size)
        controls.appRoutingSupport.setText(if (rootBackend) R.string.app_routing_root_hint else R.string.app_routing_tun_hint)
        controls.appRoutingLoading.visibility = if (loading) View.VISIBLE else View.GONE
        controls.appRoutingEmpty.visibility = if (!loading && adapter.rows.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun persistAndRender() { routing.save(configuration); render() }

    private fun toggle(entry: AppEntry) {
        if (loading) return
        val removing = isSelected(entry)
        if (rootBackend && !removing && entry.uid != null && entry.uid % 100_000 < 10_000) {
            Toast.makeText(this, R.string.app_routing_root_system_uid, Toast.LENGTH_LONG).show()
            return
        }
        val group = if (entry.uid == null) listOf(entry) else entries.filter { it.uid == entry.uid }
        val applySelection = {
            val packages = configuration.packages.toMutableSet()
            if (removing) packages.removeAll(group.map { it.packageName }.toSet())
            else packages.addAll(group.map { it.packageName })
            configuration = configuration.copy(packages = packages); persistAndRender()
        }
        if (!removing && group.size > 1) {
            val names = group.take(8).joinToString("\n") { "${it.label}\n${it.packageName}" } +
                if (group.size > 8) "\n" + getString(R.string.app_routing_shared_more, group.size - 8) else ""
            MaterialAlertDialogBuilder(this).setTitle(R.string.app_routing_shared_title)
                .setMessage(getString(R.string.app_routing_shared_message, names))
                .setNegativeButton(R.string.app_routing_cancel, null)
                .setPositiveButton(R.string.app_routing_confirm) { _, _ -> applySelection() }.show()
        } else applySelection()
    }

    override fun onDestroy() {
        loadGeneration++
        loader.shutdownNow(); icons.shutdownNow(); main.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private data class AppEntry(val packageName: String, val label: String, val uid: Int?,
                                val system: Boolean, val info: ApplicationInfo?)

    private inner class AppAdapter : RecyclerView.Adapter<AppHolder>() {
        var rows: List<AppEntry> = emptyList()
            private set

        fun replaceRows(replacement: List<AppEntry>) {
            val previousSize = rows.size
            rows = replacement
            // Keep updates local to the app rows so typing never invalidates the search header.
            notifyItemRangeChanged(0, minOf(previousSize, rows.size))
            when {
                rows.size < previousSize -> notifyItemRangeRemoved(rows.size, previousSize - rows.size)
                rows.size > previousSize -> notifyItemRangeInserted(previousSize, rows.size - previousSize)
            }
        }

        override fun getItemCount() = rows.size
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = AppHolder(
            LayoutInflater.from(parent.context).inflate(R.layout.item_app_routing, parent, false))
        override fun onBindViewHolder(holder: AppHolder, position: Int) {
            val entry = rows[position]
            val selected = isSelected(entry)
            val restricted = rootBackend && entry.uid != null && entry.uid % 100_000 < 10_000 && !selected
            val editable = !loading && !restricted
            val card = holder.card
            // MaterialCardView only updates checked state while enabled. Reset recycled rows before disabling.
            card.isEnabled = true
            card.isChecked = selected
            card.isEnabled = editable
            holder.label.text = entry.label
            holder.packageName.text = buildString {
                append(entry.packageName)
                if (entry.system) append(" · ").append(getString(R.string.app_routing_system_marker))
                if (restricted) append("\n").append(getString(R.string.app_routing_root_system_uid))
                else if (entry.uid != null && entries.count { it.uid == entry.uid } > 1)
                    append("\n").append(getString(R.string.app_routing_shared_marker, entry.uid))
            }
            holder.packageName.maxLines = if (restricted) 3 else 2
            holder.check.isChecked = selected
            holder.check.isEnabled = editable
            card.contentDescription = getString(R.string.app_routing_row_accessibility, entry.label, holder.packageName.text)
            card.stateDescription = if (restricted) getString(R.string.app_routing_root_system_uid) else null
            card.setOnClickListener { toggle(entry) }
            holder.icon.tag = entry.packageName
            holder.icon.setImageDrawable(iconCache.get(entry.packageName) ?: packageManager.defaultActivityIcon)
            if (entry.info != null && iconCache.get(entry.packageName) == null && pendingIcons.add(entry.packageName)) {
                icons.execute {
                    val icon = runCatching { entry.info.loadIcon(packageManager) }.getOrNull()
                    pendingIcons.remove(entry.packageName)
                    if (icon == null) return@execute
                    iconCache.put(entry.packageName, icon)
                    main.post {
                        if (!isDestroyed && holder.icon.tag == entry.packageName) holder.icon.setImageDrawable(icon)
                    }
                }
            }
        }
    }

    private class AppRoutingControlsAdapter(private val controls: View) :
        RecyclerView.Adapter<RecyclerView.ViewHolder>() {
        override fun getItemCount() = 1

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val container = FrameLayout(parent.context).apply {
                layoutParams = RecyclerView.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                )
            }
            return object : RecyclerView.ViewHolder(container) {}
        }

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            val container = holder.itemView as FrameLayout
            if (controls.parent === container) return
            (controls.parent as? ViewGroup)?.removeView(controls)
            container.addView(controls, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        }
    }

    private class AppHolder(view: View) : RecyclerView.ViewHolder(view) {
        val card = view as MaterialCardView
        val icon: ImageView = view.findViewById(R.id.appRoutingIcon)
        val label: TextView = view.findViewById(R.id.appRoutingLabel)
        val packageName: TextView = view.findViewById(R.id.appRoutingPackage)
        val check: MaterialCheckBox = view.findViewById(R.id.appRoutingSelected)
    }

    private companion object {
        const val STATE_SEARCH_QUERY = "app_routing_search_query"
    }
}
