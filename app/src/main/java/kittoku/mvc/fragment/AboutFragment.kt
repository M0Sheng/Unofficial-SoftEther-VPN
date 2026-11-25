package kittoku.mvc.fragment

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.PreferenceFragmentCompat
import com.google.android.material.color.MaterialColors
import kittoku.mvc.R


internal class AboutFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        val page = preferenceManager.createPreferenceScreen(requireContext())
        val information = PreferenceCategory(requireContext()).apply {
            layoutResource = R.layout.preference_material3_category
            isIconSpaceReserved = false
        }
        page.addPreference(information)
        information.addPreference(Preference(requireContext()).apply {
            setTitle(R.string.pref_about)
            setSummary(R.string.about_description)
            isSelectable = false
            layoutResource = R.layout.preference_material3_row
            isIconSpaceReserved = false
        })
        page.addPreference(Preference(requireContext()).apply {
            setTitle(R.string.privacy_summary_title)
            setSummary(R.string.privacy_summary)
            isSelectable = false
            layoutResource = R.layout.preference_material3_row
            isIconSpaceReserved = false
        })
        page.addPreference(Preference(requireContext()).apply {
            setTitle(R.string.about_softether_project)
            val project = "github.com/SoftEtherVPN/SoftEtherVPN"
            summary = project
            intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://$project"))
            layoutResource = R.layout.preference_material3_row
            isIconSpaceReserved = false
        })
        preferenceScreen = page
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setDivider(null)
        setDividerHeight(0)
        val background = MaterialColors.getColor(view, com.google.android.material.R.attr.colorSurface)
        view.setBackgroundColor(background)
        listView.apply {
            setBackgroundColor(background)
            clipToPadding = false
            setPaddingRelative(0, 0, 0, resources.getDimensionPixelSize(R.dimen.ui_page_inset))
        }
    }

}
