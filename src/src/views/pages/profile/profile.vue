<template>
  <div class="tfe-profile-page">
    <div class="profile-area">
      <div class="cover">
        <n-avatar :text-fallback="user?.display_name" round :src="avatarUrl" :size="82"></n-avatar>
      </div>
      <div class="basic-info">
        <h2>{{ user?.display_name }}</h2>
        <span>{{ user?.user_id }}</span>
      </div>
    </div>
    <div class="right-area">
      <n-card class="first-block right-block" title="Banner 1"> Banner with stuff </n-card>
      <n-card class="second-block right-block" title="Lastest Activity"> Activities </n-card>
      <n-card class="third-block right-block" title="Websites & Links"> Links </n-card>
    </div>
  </div>
</template>

<script setup lang="ts">
  import { GetMxImage, SearchUsers, getUserId } from '@/helpers/matrix';
  import NAvatar from '@components/avatar/avatar.vue';
  import { NCard, NTag } from 'naive-ui';
  import { inject, ref, watch } from 'vue';
  import { onBeforeRouteUpdate, useRoute } from 'vue-router';
  import { UserSearched } from '@/models/matrix';

  const route = useRoute();
  const user = ref<UserSearched>();
  const avatarUrl = ref('');

  const addToSearch = inject<any>('addToSearch');

  const fallbackNoParam = (paramId: string) => {
    let _id = paramId;
    if (!_id) {
      _id = getUserId();
    }

    return _id;
  };

  const OnPageLoaded = async (paramId: string) => {
    user.value = (await SearchUsers(fallbackNoParam(paramId), 1))[0];
  };

  watch(user, (value) => {
    avatarUrl.value = GetMxImage(value?.avatar_url) || '';
  });

  OnPageLoaded(route.params['userId']?.toString());

  onBeforeRouteUpdate((to) => {
    OnPageLoaded(to.params['userId']?.toString());
  });
</script>
<style lang="scss" src="./profile.scss" scoped></style>
