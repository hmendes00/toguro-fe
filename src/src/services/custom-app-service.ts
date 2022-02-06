import { CustomApp } from '@/store/modules/app/state';
import fakeApi from '@assets/fake-api.json';

const CustomAppService = {
  getAllFor: (target: string): CustomApp[] => {
    //call to API to get apps for user by target e.g = "home" or "menu", etc
    return fakeApi.customApps.getMyCustomApps;
  },
  addScriptToHead(customApp: CustomApp) {
    const appScript = document.createElement('script');
    appScript.type = customApp.appUrl.endsWith('.ts') ? 'module' : 'text/javascript';
    appScript.setAttribute('src', customApp.appUrl);
    appScript.setAttribute('data-appid', customApp.appId);
    appScript.setAttribute('data-appName', customApp.appName);
    document.head.appendChild(appScript);
  }
};

export default CustomAppService;
