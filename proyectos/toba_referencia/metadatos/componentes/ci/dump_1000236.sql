------------------------------------------------------------
--[1000236]--  ABM Multi-Tabla 
------------------------------------------------------------
INSERT INTO apex_objeto (proyecto, objeto, anterior, reflexivo, clase_proyecto, clase, subclase, subclase_archivo, objeto_categoria_proyecto, objeto_categoria, nombre, titulo, colapsable, descripcion, fuente_datos_proyecto, fuente_datos, solicitud_registrar, solicitud_obj_obs_tipo, solicitud_obj_observacion, parametro_a, parametro_b, parametro_c, parametro_d, parametro_e, parametro_f, usuario, creacion) VALUES ('toba_referencia', '1000236', NULL, NULL, 'toba', 'objeto_ci', NULL, NULL, NULL, NULL, 'ABM Multi-Tabla', NULL, '0', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2007-02-05 15:46:59');
INSERT INTO apex_objeto_mt_me (objeto_mt_me_proyecto, objeto_mt_me, ev_procesar_etiq, ev_cancelar_etiq, ancho, alto, posicion_botonera, tipo_navegacion, con_toc, incremental, debug_eventos, activacion_procesar, activacion_cancelar, ev_procesar, ev_cancelar, objetos, post_procesar, metodo_despachador, metodo_opciones) VALUES ('toba_referencia', '1000236', NULL, NULL, '80%', NULL, 'abajo', 'wizard', '0', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
INSERT INTO apex_objeto_ci_pantalla (objeto_ci_proyecto, objeto_ci, pantalla, identificador, orden, etiqueta, descripcion, tip, imagen_recurso_origen, imagen, objetos, eventos, subclase, subclase_archivo) VALUES ('toba_referencia', '1000236', '1000122', 'agenda', '1', 'Agenda', NULL, NULL, NULL, NULL, NULL, NULL, 'pant_agenda', 'tutorial/pant_tutorial.php');
INSERT INTO apex_objeto_ci_pantalla (objeto_ci_proyecto, objeto_ci, pantalla, identificador, orden, etiqueta, descripcion, tip, imagen_recurso_origen, imagen, objetos, eventos, subclase, subclase_archivo) VALUES ('toba_referencia', '1000236', '1000123', 'introduccion', '2', 'Introducci�n', NULL, NULL, NULL, NULL, NULL, NULL, 'pant_introduccion', 'tutorial/abm_mt/pantallas.php');
INSERT INTO apex_objeto_ci_pantalla (objeto_ci_proyecto, objeto_ci, pantalla, identificador, orden, etiqueta, descripcion, tip, imagen_recurso_origen, imagen, objetos, eventos, subclase, subclase_archivo) VALUES ('toba_referencia', '1000236', '1000125', 'def_relacion', '3', '[Video] Definici�n de la relaci�n', NULL, NULL, NULL, NULL, NULL, NULL, 'pant_def_relacion', 'tutorial/abm_mt/pantallas.php');
INSERT INTO apex_objeto_ci_pantalla (objeto_ci_proyecto, objeto_ci, pantalla, identificador, orden, etiqueta, descripcion, tip, imagen_recurso_origen, imagen, objetos, eventos, subclase, subclase_archivo) VALUES ('toba_referencia', '1000236', '1000126', 'ci_seleccion', '4', 'Extensi�n del Ci de Navegaci�n/Selecci�n', NULL, NULL, NULL, NULL, NULL, NULL, 'pant_ci_seleccion', 'tutorial/abm_mt/pantallas.php');
INSERT INTO apex_objeto_ci_pantalla (objeto_ci_proyecto, objeto_ci, pantalla, identificador, orden, etiqueta, descripcion, tip, imagen_recurso_origen, imagen, objetos, eventos, subclase, subclase_archivo) VALUES ('toba_referencia', '1000236', '1000127', 'ci_edicion', '5', 'Extensi�n del Ci de Edici�n', NULL, NULL, NULL, NULL, NULL, NULL, 'pant_ci_edicion', 'tutorial/abm_mt/pantallas.php');
