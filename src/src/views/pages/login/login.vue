<template>
  <div ref="root" class="tfe-login-page">
    <p v-if="!loginApp">
      You don't have apps to load here. Either modify the page yourself or add an app that matches this target and type
    </p>
  </div>
</template>

<style lang="scss" src="./login.scss" scoped></style>
<script setup lang="ts">
  import CustomAppService from '@/services/custom-app-service';
  import { appStore } from '@/store';
  import { computed, onMounted, ref } from 'vue';

  const root = ref<HTMLDivElement>();
  const loginApp = computed(() =>
    Object.values(appStore.state.customApps).find((app) => app.target === 'route' && app.appType === 'login')
  );

  onMounted(() => {
    if (loginApp.value) {
      CustomAppService.addCustomAppTag(root.value!, loginApp.value);
    }
  });
</script>
