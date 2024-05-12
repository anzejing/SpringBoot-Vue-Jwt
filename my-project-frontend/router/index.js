import {createRouter, createWebHistory} from "vue-router"
import {unauthorized} from "@/net/index.js";

const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes: [
        {
            path: '/',
            name: 'welcome',
            component: ()=>import('@/views/WelconeView.vue'),
            children: [
                {
                    path:'',
                    name: 'welcome-login',
                    component:()=>import('@/views/welcome/LoginPage.vue')
                }

            ]
        },
        {
            path: '/index',
            name: 'index',
            component:() => import('@/views/indexView.vue')

        }
    ]

})

router.beforeEach((to,from,next) =>{
    const isUnauthorized = unauthorized()
    if(to.name.startsWith('welcome-') && !isUnauthorized){
        next('/index')
    }else if (to.path.startsWith('/index') && isUnauthorized){
        next('/')
    }else {
        next()
    }
})

export default router