# Conditions d’Utilisation – ClandestineCore / ClandestineDoc

En utilisant ce projet, vous acceptez les termes et conditions suivants.  
**Si vous êtes en désaccord avec l’un d’eux, n’utilisez pas ce projet.**

---

## 1. Objectif du projet

**ClandestineCore** est un rootkit kernel modulaire à vocation **éducative** et **recherche** uniquement.  
Son but est de **démontrer, documenter et explorer** des techniques avancées de manipulation du noyau Linux, telles que :
- Hook sur fonctions noyau (`kprobe`)
- Disparition de module (`list_del(&THIS_MODULE->list)`)
- Communication avec l’espace utilisateur (IOCTL / misc device)
- Envoi réseau noyau (`kernel_sendmsg`)
- Furtivité et persistence au niveau kernel

Ce projet est conçu pour :
- Des **recherches en cybersécurité avancée**
- Des **exercices de reverse engineering kernel**
- Des **études de détection & anti-rootkit**

---

## 2. Restrictions d’utilisation

- **Ce code est réservé à un usage en laboratoire de test, sur des systèmes que vous possédez ou pour lesquels vous avez une autorisation explicite.**
- **Interdiction formelle** de l’utiliser pour compromettre un système sans consentement.
- Le projet ne doit **pas être utilisé à des fins malveillantes** ou dans un environnement de production.
- **Respect strict de la législation** en vigueur dans votre juridiction (notamment en matière de sécurité des systèmes d'information).
- Il est **vivement recommandé** d’utiliser ce projet dans une machine virtuelle, un environnement isolé, ou un sandbox.

---

## 3. Aucune garantie, aucune responsabilité

- Ce projet est fourni **"tel quel"**, **sans garantie d’aucune sorte**, explicite ou implicite.
- L’auteur (**Rzdhop**) **décline toute responsabilité** en cas :
  - de perte de données
  - de corruption système
  - de crash kernel ou panics
  - de détection ou signalement par un antivirus ou une solution EDR
  - de dommages matériels ou logiciels liés à l’utilisation du code

---

## 4. Cadre éthique

En utilisant **ClandestineCore**, vous vous engagez à :
- **Ne jamais utiliser ce projet hors cadre légal ou éthique**
- L’utiliser **uniquement à des fins pédagogiques ou de recherche**
- Ne **pas dériver ce code** pour en faire un
