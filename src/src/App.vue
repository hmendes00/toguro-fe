<template>
  <div class="tfe-app">
    <tfe-default-layout v-if="isLoggedIn || router.currentRoute.value.name === 'login'" />
    <n-skeleton v-else height="52px" />
  </div>
</template>

<script setup lang="ts">
  import TfeDefaultLayout from '@layouts/default/default.vue';
  import { registerGlobalListeners, removeGlobalListeners } from '@/helpers/global-listeners';
  import { computed, onMounted, onUnmounted, watch } from 'vue';
  import { NSkeleton } from 'naive-ui';
  import { appStore, selfStore } from './store';
  import router from './router';
  import CustomAppService from './services/custom-app-service';
  import { LOAD_CUSTOM_APPS } from './store/modules/app/actions';
  import { getUserId } from './helpers/matrix';

  const isLoggedIn = computed<boolean>(() => selfStore.getters['isLoggedIn']);

  const userId = getUserId();
  if (!userId && !isLoggedIn.value && router.currentRoute.value.name !== 'login') {
    router.push('/login');
  }

  onMounted(() => {
    registerGlobalListeners();
    appStore.dispatch(LOAD_CUSTOM_APPS);
  });

  onUnmounted(() => {
    removeGlobalListeners();
  });

  /**
   * Register/Load required-globally apps. e.g. apps that dispatches global-events
   * Login-apps are an example of it knowing they will dispatch the event for login-updated
   * This won't necessarily instantiate the app, but register it.
   */
  watch(appStore.state.customApps, (apps) => {
    Object.values(apps)
      .filter((app) => {
        return app.requiredGlobally;
      })
      .forEach((app) => {
        CustomAppService.addScriptToHead(app);
      });
  });
</script>

<style lang="scss">
  @import '@styles/reset.scss';
  @import '@styles/variables.scss';

  .tfe-app {
    font-family: -apple-system, BlinkMacSystemFont, 'San Francisco', Helvetica, Arial, sans-serif;
    font-weight: 300;
    background-color: $font-lighter;

    a {
      color: $primary;
      text-decoration: none;
    }
  }
</style>
