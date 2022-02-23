<template>
  <div class="tfe-profile-page">
    <div class="profile-area">
      <div class="cover">
        <n-avatar :text-fallback="user?.displayName" round :src="avatarUrl" :size="82"></n-avatar>
      </div>
      <div class="basic-info">
        <h2>{{ user?.displayName }}</h2>
        <span> Developer </span>
      </div>
      <div class="main-content">test</div>
    </div>
    <div class="right-area">
      <n-card class="skill-tags right-block" title="Relevant Skills">
        <div class="tags">
          <n-tag type="success" @click="addToSearch('VueJS3')">VueJS3</n-tag>
          <n-tag type="success" @click="addToSearch('VueJS2')">VueJS2</n-tag>
          <n-tag type="success" @click="addToSearch('Typescript')">Typescript</n-tag>
          <n-tag type="success" @click="addToSearch('NodeJS')">NodeJS</n-tag>
          <n-tag type="success" @click="addToSearch('Javascript')">Javascript</n-tag>
          <n-tag type="success" @click="addToSearch('AWS-CDK')">AWS-CDK</n-tag>
        </div>
      </n-card>
      <n-card class="latest-assessments-area right-block" title="Latest Assessments"> </n-card>
      <n-card class="portfolio-area right-block" title="Websites & Links"> </n-card>
    </div>
  </div>
</template>

<script setup lang="ts">
  import { GetMxImage, GetUserById, getUserId } from '@/helpers/matrix';
  import NAvatar from '@components/avatar/avatar.vue';
  import { NCard, NTag } from 'naive-ui';
  import { inject, ref, watch } from 'vue';
  import { onBeforeRouteUpdate, useRoute } from 'vue-router';
  import { User } from 'matrix-js-sdk';

  const route = useRoute();
  const user = ref<User>();
  const avatarUrl = ref('');

  const addToSearch = inject<any>('addToSearch');

  const fallbackNoParam = (paramId: string) => {
    let _id = paramId;
    if (!_id) {
      _id = getUserId();
    }

    return _id;
  };

  const OnPageLoaded = (paramId: string) => {
    user.value = GetUserById(fallbackNoParam(paramId));
  };

  watch(user, (value) => {
    avatarUrl.value = GetMxImage(value?.avatarUrl) || '';
  });

  OnPageLoaded(route.params['userId']?.toString());

  onBeforeRouteUpdate((to) => {
    OnPageLoaded(to.params['userId']?.toString());
  });
</script>
<style lang="scss" src="./profile.scss" scoped></style>
