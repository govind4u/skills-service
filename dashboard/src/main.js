/*
 * Copyright 2020 SkillTree
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// The Vue build version to load with the `import` command
// (runtime-only or standalone) has been set in webpack.base.conf with an alias.
import Vue from 'vue';
import {
  ButtonPlugin,
  ToastPlugin,
  ButtonGroupPlugin,
  TooltipPlugin,
  ModalPlugin,
  LayoutPlugin,
  FormRadioPlugin,
  AlertPlugin,
  FormSelectPlugin,
  SpinnerPlugin,
  TabsPlugin,
  FormTextareaPlugin,
  LinkPlugin,
  DropdownPlugin,
  AvatarPlugin,
  TablePlugin,
  FormInputPlugin,
  FormCheckboxPlugin,
  InputGroupPlugin,
  CardPlugin,
  PaginationPlugin,
  CollapsePlugin,
  OverlayPlugin,
  BadgePlugin,
  PopoverPlugin,
  FormPlugin,
  FormGroupPlugin,
  FormDatepickerPlugin,
  ProgressPlugin,
  BIcon,
  BIconQuestion,
} from 'bootstrap-vue';

import { SkillsConfiguration, SkillsDirective, SkillsReporter } from '@skilltree/skills-client-vue';
import {
  localize, ValidationProvider, ValidationObserver, setInteractionMode,
} from 'vee-validate';
import en from 'vee-validate/dist/locale/en.json';
import Vuex from 'vuex';
import marked from 'marked';
import VueApexCharts from 'vue-apexcharts';
import FiltersPlugin from '@/common-components/filter/FiltersPlugin';
import dayjs from '@/common-components/DayJsCustomizer';
import InceptionConfigurer from './InceptionConfigurer';
import 'babel-polyfill';
import 'matchmedia-polyfill';
import 'matchmedia-polyfill/matchMedia.addListener';
// import './filters/NumberFilter';
import './filters/TruncateFilter';
import './filters/DateFilter';
// import './filters/TimeFromNowFilter';
import './directives/SkillsOnMountDirective';
import RegisterValidators from './validators/RegisterValidators';
import './directives/FocusDirective';
import App from './App';
import router from './router';
import store from './store/store';

Vue.component('apexchart', VueApexCharts);
Vue.component('ValidationProvider', ValidationProvider);
Vue.component('ValidationObserver', ValidationObserver);
Vue.use(Vuex);

Vue.use(ButtonPlugin);
Vue.use(ToastPlugin);
Vue.use(TooltipPlugin);
Vue.use(LayoutPlugin);
Vue.use(FormRadioPlugin);
Vue.use(AlertPlugin);
Vue.use(FormSelectPlugin);
Vue.use(ModalPlugin);
Vue.use(SpinnerPlugin);
Vue.use(TabsPlugin);
Vue.use(FormTextareaPlugin);
Vue.use(LinkPlugin);
Vue.use(DropdownPlugin);
Vue.use(AvatarPlugin);
Vue.use(ButtonGroupPlugin);
Vue.use(TablePlugin);
Vue.use(FormInputPlugin);
Vue.use(InputGroupPlugin);
Vue.use(FormCheckboxPlugin);
Vue.use(CardPlugin);
Vue.use(PaginationPlugin);
Vue.use(CollapsePlugin);
Vue.use(OverlayPlugin);
Vue.use(BadgePlugin);
Vue.use(PopoverPlugin);
Vue.use(FormPlugin);
Vue.use(FormGroupPlugin);
Vue.use(FormDatepickerPlugin);
Vue.use(ProgressPlugin);
Vue.component('BIcon', BIcon);
Vue.component('BIconQuestion', BIconQuestion);

Vue.use(SkillsDirective);
Vue.use(FiltersPlugin);

localize({
  en,
});

setInteractionMode('custom', () => ({ on: ['input', 'change'] }));
Vue.config.productionTip = false;
window.dayjs = dayjs;

window.axios = require('axios');
require('./interceptors/errorHandler');
require('./interceptors/clientVersionInterceptor');
require('./interceptors/userAgreementInterceptor');
require('vue-multiselect/dist/vue-multiselect.min.css');

const isActiveProjectIdChange = (to, from) => to.params.projectId !== from.params.projectId;
const isLoggedIn = () => store.getters.isAuthenticated;
const isPki = () => store.getters.isPkiAuthenticated;
const getLandingPage = () => {
  let landingPage = 'MyProgressPage';
  if (store.getters.userInfo) {
    if (store.getters.userInfo.landingPage === 'admin') {
      landingPage = 'AdminHomePage';
    }
  }
  return landingPage;
};

const registrationId = () => store.getters.config.saml2RegistrationId;
const isSaml2 = () => store.getters.isSaml2Authenticated;

router.beforeEach((to, from, next) => {
  const { skillsClientDisplayPath } = to.query;
  store.commit('skillsClientDisplayPath', { path: skillsClientDisplayPath, fromDashboard: true });

  const requestAccountPath = '/request-root-account';
  if (isSaml2() && !isLoggedIn() && to.path !== requestAccountPath && store.getters.config.needToBootstrap) {
    window.location = `/saml2/authenticate/${registrationId()}`;
  } else if (!isPki() && !isLoggedIn() && to.path !== requestAccountPath && store.getters.config.needToBootstrap) {
    next({ path: requestAccountPath });
  } else if (!isPki() && to.path === requestAccountPath && !store.getters.config.needToBootstrap) {
    next({ name: getLandingPage() });
  } else {
    /* eslint-disable no-lonely-if */
    if (store.state.showUa && (to.path !== '/user-agreement' && to.path !== '/skills-login')) {
      let p = '';
      if (to.query?.redirect) {
        p = to.query.redirect;
      } else {
        p = to.fullPath;
      }
      const ua = p !== '/' ? { name: 'UserAgreement', query: { redirect: p } } : { name: 'UserAgreement' };
      next(ua);
    } else {
      if (to.path === '/') {
        const landingPageRoute = { name: getLandingPage() };
        next(landingPageRoute);
      }
      if (from.path !== '/error') {
        store.commit('previousUrl', from.fullPath);
      }
      if (isActiveProjectIdChange(to, from)) {
        store.commit('currentProjectId', to.params.projectId);
      }
      if (to.matched.some((record) => record.meta.requiresAuth)) {
        // this route requires auth, check if logged in if not, redirect to login page.
        if (!isLoggedIn()) {
          const newRoute = { query: { redirect: to.fullPath } };
          if (isPki()) {
            newRoute.name = getLandingPage();
          } else if (isSaml2()) {
            window.location = `/saml2/authenticate/${registrationId()}`;
          } else {
            newRoute.name = 'Login';
          }
          next(newRoute);
        } else {
          next();
        }
      } else {
        next();
      }
    }
  }
});

router.afterEach((to) => {
  if (to.meta.reportSkillId) {
    SkillsConfiguration.afterConfigure()
      .then(() => {
        SkillsReporter.reportSkill(to.meta.reportSkillId);
      });
  }
});

const renderer = new marked.Renderer();
renderer.link = function markedLinkRenderer(href, title, text) {
  let titleRes = title;
  if (!title) {
    titleRes = text;
  }
  const link = marked.Renderer.prototype.link.call(this, href, titleRes, text);
  let resLink = link.replace('<a', "<a target='_blank' ");
  resLink = resLink.replace('</a>', ' <i class="fas fa-external-link-alt" style="font-size: 0.8rem"></i></a>');
  return resLink;
};
marked.setOptions({
  renderer,
});

store.dispatch('loadConfigState').finally(() => {
  RegisterValidators.init();
  store.dispatch('restoreSessionIfAvailable').finally(() => {
    InceptionConfigurer.configure();
    /* eslint-disable no-new */
    const vm = new Vue({
      el: '#app',
      router,
      components: { App },
      template: '<App/>',
      store,
    });
    window.vm = vm;
  });
});
