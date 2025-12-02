using System;
using System.Security.Principal;
using System.Text;
using System.Web;
using System.Web.Services;
using System.Xml;
using Microsoft.SharePoint.Administration;

namespace Microsoft.SharePoint.SoapServer;

[WebService(Namespace = "http://schemas.microsoft.com/sharepoint/soap/")]
public class Admin : WebService
{
	internal const string KEY_SPGLOBALADMIN = "Microsoft.SharePoint.Admin.GlobalAdmin";

	[WebMethod]
	public string CreateSite(string Url, string Title, string Description, int Lcid, string WebTemplate, string OwnerLogin, string OwnerName, string OwnerEmail, string PortalUrl, string PortalName)
	{
		EnsureNTAuthentication(base.Context);
		try
		{
			Uri uri = new Uri(Url);
			bool flag = false;
			if (PortalUrl != null && PortalUrl.Length != 0 && PortalName != null && PortalName.Length != 0)
			{
				flag = true;
			}
			SPWebApplication val = SPWebApplication.Lookup(uri);
			if ((SPPersistedObject)(object)val == (SPPersistedObject)null)
			{
				throw new ArgumentException();
			}
			SPSite val2 = val.Sites.Add(uri.ToString(), Title, Description, (uint)Lcid, WebTemplate, OwnerLogin, OwnerName, OwnerEmail);
			try
			{
				if (flag)
				{
					val2.PortalUrl = PortalUrl;
					val2.PortalName = PortalName;
				}
				return val2.Url;
			}
			finally
			{
				val2.Close();
			}
		}
		catch (Exception ex)
		{
			throw SoapServerException.HandleException(ex);
		}
	}

	[WebMethod]
	public void DeleteSite(string Url)
	{
		//IL_002e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0034: Expected O, but got Unknown
		EnsureNTAuthentication(base.Context);
		try
		{
			Uri uri = new Uri(Url);
			SPWebApplication val = SPWebApplication.Lookup(uri);
			if ((SPPersistedObject)(object)val == (SPPersistedObject)null)
			{
				throw new ArgumentException();
			}
			SPSiteAdministration val2 = new SPSiteAdministration(uri.ToString());
			try
			{
				val2.Delete();
			}
			finally
			{
				((IDisposable)val2)?.Dispose();
			}
		}
		catch (Exception ex)
		{
			throw SoapServerException.HandleException(ex);
		}
	}

	[WebMethod]
	public XmlDocument GetLanguages()
	{
		//IL_003c: Unknown result type (might be due to invalid IL or missing references)
		//IL_0042: Expected O, but got Unknown
		EnsureNTAuthentication(base.Context);
		try
		{
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append("<Languages xmlns=\"http://schemas.microsoft.com/sharepoint/soap/\">");
			SPGlobalAdmin contextGlobalAdmin = GetContextGlobalAdmin();
			SPLanguageCollection installedLanguages = contextGlobalAdmin.InstalledLanguages;
			foreach (SPLanguage item in (SPBaseCollection)installedLanguages)
			{
				SPLanguage val = item;
				stringBuilder.Append("<LCID>" + val.LCID + "</LCID>");
			}
			stringBuilder.Append("</Languages>");
			XmlDocument xmlDocument = new XmlDocument();
			xmlDocument.LoadXml(stringBuilder.ToString());
			return xmlDocument;
		}
		catch (Exception ex)
		{
			throw SoapServerException.HandleException(ex);
		}
	}

	[Obsolete("Cache refresh occurs automatically after every update.", false)]
	[WebMethod]
	public void RefreshConfigCache(Guid VirtualServerId, bool AdminGroupChanged)
	{
	}

	private SPGlobalAdmin GetContextGlobalAdmin()
	{
		//IL_001e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0024: Expected O, but got Unknown
		object obj = base.Context.Items["Microsoft.SharePoint.Admin.GlobalAdmin"];
		SPGlobalAdmin val = (SPGlobalAdmin)((obj is SPGlobalAdmin) ? obj : null);
		if (val == null)
		{
			val = new SPGlobalAdmin();
			base.Context.Items["Microsoft.SharePoint.Admin.GlobalAdmin"] = val;
		}
		return val;
	}

	private static void EnsureNTAuthentication(HttpContext context)
	{
		if (!(context.User.Identity is WindowsIdentity))
		{
			context.Response.Clear();
			context.Response.StatusCode = 403;
			context.Response.Flush();
			context.Response.End();
		}
		WindowsIdentity windowsIdentity = (WindowsIdentity)context.User.Identity;
		if (windowsIdentity.IsAnonymous || !windowsIdentity.IsAuthenticated)
		{
			context.Response.Clear();
			context.Response.StatusCode = 401;
			context.Response.Flush();
			context.Response.End();
		}
	}
}
