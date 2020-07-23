!function (e) {
    var t = {};

    function o(n) {
        if (t[n]) return t[n].exports;
        var r = t[n] = {i: n, l: !1, exports: {}};
        return e[n].call(r.exports, r, r.exports, o), r.l = !0, r.exports
    }

    o.m = e, o.c = t, o.d = function (e, t, n) {
        o.o(e, t) || Object.defineProperty(e, t, {configurable: !1, enumerable: !0, get: n})
    }, o.r = function (e) {
        Object.defineProperty(e, "__esModule", {value: !0})
    }, o.n = function (e) {
        var t = e && e.__esModule ? function () {
            return e.default
        } : function () {
            return e
        };
        return o.d(t, "a", t), t
    }, o.o = function (e, t) {
        return Object.prototype.hasOwnProperty.call(e, t)
    }, o.p = "", o(o.s = 21)
}([function (e, t, o) {
    "use strict";
    var n;
    t.__esModule = !0, function (e) {
        e[e.Before = 1] = "Before", e[e.After = 2] = "After", e[e.Inside = 3] = "Inside", e[e.None = 4] = "None"
    }(n = t.Position || (t.Position = {})), t.position_names = {
        before: n.Before,
        after: n.After,
        inside: n.Inside,
        none: n.None
    }, t.getPositionName = function (e) {
        for (var o in t.position_names) if (t.position_names.hasOwnProperty(o) && t.position_names[o] === e) return o;
        return ""
    }, t.getPosition = function (e) {
        return t.position_names[e]
    };
    var r = function () {
        function e(t, o, n) {
            void 0 === o && (o = !1), void 0 === n && (n = e), this.name = "", this.setData(t), this.children = [], this.parent = null, o && (this.id_mapping = {}, this.tree = this, this.node_class = n)
        }

        return e.prototype.setData = function (e) {
            var t = this, o = function (e) {
                null != e && (t.name = e)
            };
            if (e) if ("object" != typeof e) o(e); else for (var n in e) if (e.hasOwnProperty(n)) {
                var r = e[n];
                "label" === n ? o(r) : "children" !== n && (this[n] = r)
            }
        }, e.prototype.loadFromData = function (e) {
            this.removeChildren();
            for (var t = 0, o = e; t < o.length; t++) {
                var n = o[t], r = new this.tree.node_class(n);
                this.addChild(r), "object" == typeof n && n.children && r.loadFromData(n.children)
            }
        }, e.prototype.addChild = function (e) {
            this.children.push(e), e._setParent(this)
        }, e.prototype.addChildAtPosition = function (e, t) {
            this.children.splice(t, 0, e), e._setParent(this)
        }, e.prototype.removeChild = function (e) {
            e.removeChildren(), this._removeChild(e)
        }, e.prototype.getChildIndex = function (e) {
            return jQuery.inArray(e, this.children)
        }, e.prototype.hasChildren = function () {
            return 0 !== this.children.length
        }, e.prototype.isFolder = function () {
            return this.hasChildren() || this.load_on_demand
        }, e.prototype.iterate = function (e) {
            var t = function (o, n) {
                if (o.children) for (var r = 0, i = o.children; r < i.length; r++) {
                    var s = i[r];
                    e(s, n) && s.hasChildren() && t(s, n + 1)
                }
            };
            t(this, 0)
        }, e.prototype.moveNode = function (e, t, o) {
            e.parent && !e.isParentOf(t) && (e.parent._removeChild(e), o === n.After ? t.parent && t.parent.addChildAtPosition(e, t.parent.getChildIndex(t) + 1) : o === n.Before ? t.parent && t.parent.addChildAtPosition(e, t.parent.getChildIndex(t)) : o === n.Inside && t.addChildAtPosition(e, 0))
        }, e.prototype.getData = function (e) {
            function t(e) {
                return e.map(function (e) {
                    var o = {};
                    for (var n in e) if (-1 === ["parent", "children", "element", "tree"].indexOf(n) && Object.prototype.hasOwnProperty.call(e, n)) {
                        var r = e[n];
                        o[n] = r
                    }
                    return e.hasChildren() && (o.children = t(e.children)), o
                })
            }

            return void 0 === e && (e = !1), t(e ? [this] : this.children)
        }, e.prototype.getNodeByName = function (e) {
            return this.getNodeByCallback(function (t) {
                return t.name === e
            })
        }, e.prototype.getNodeByCallback = function (e) {
            var t = null;
            return this.iterate(function (o) {
                return !e(o) || (t = o, !1)
            }), t
        }, e.prototype.addAfter = function (e) {
            if (this.parent) {
                var t = new this.tree.node_class(e), o = this.parent.getChildIndex(this);
                return this.parent.addChildAtPosition(t, o + 1), "object" == typeof e && e.children && e.children.length && t.loadFromData(e.children), t
            }
            return null
        }, e.prototype.addBefore = function (e) {
            if (this.parent) {
                var t = new this.tree.node_class(e), o = this.parent.getChildIndex(this);
                return this.parent.addChildAtPosition(t, o), "object" == typeof e && e.children && e.children.length && t.loadFromData(e.children), t
            }
            return null
        }, e.prototype.addParent = function (e) {
            if (this.parent) {
                var t = new this.tree.node_class(e);
                t._setParent(this.tree);
                for (var o = this.parent, n = 0, r = o.children; n < r.length; n++) {
                    var i = r[n];
                    t.addChild(i)
                }
                return o.children = [], o.addChild(t), t
            }
            return null
        }, e.prototype.remove = function () {
            this.parent && (this.parent.removeChild(this), this.parent = null)
        }, e.prototype.append = function (e) {
            var t = new this.tree.node_class(e);
            return this.addChild(t), "object" == typeof e && e.children && e.children.length && t.loadFromData(e.children), t
        }, e.prototype.prepend = function (e) {
            var t = new this.tree.node_class(e);
            return this.addChildAtPosition(t, 0), "object" == typeof e && e.children && e.children.length && t.loadFromData(e.children), t
        }, e.prototype.isParentOf = function (e) {
            for (var t = e.parent; t;) {
                if (t === this) return !0;
                t = t.parent
            }
            return !1
        }, e.prototype.getLevel = function () {
            for (var e = 0, t = this; t.parent;) e += 1, t = t.parent;
            return e
        }, e.prototype.getNodeById = function (e) {
            return this.id_mapping[e]
        }, e.prototype.addNodeToIndex = function (e) {
            null != e.id && (this.id_mapping[e.id] = e)
        }, e.prototype.removeNodeFromIndex = function (e) {
            null != e.id && delete this.id_mapping[e.id]
        }, e.prototype.removeChildren = function () {
            var e = this;
            this.iterate(function (t) {
                return e.tree.removeNodeFromIndex(t), !0
            }), this.children = []
        }, e.prototype.getPreviousSibling = function () {
            if (this.parent) {
                var e = this.parent.getChildIndex(this) - 1;
                return e >= 0 ? this.parent.children[e] : null
            }
            return null
        }, e.prototype.getNextSibling = function () {
            if (this.parent) {
                var e = this.parent.getChildIndex(this) + 1;
                return e < this.parent.children.length ? this.parent.children[e] : null
            }
            return null
        }, e.prototype.getNodesByProperty = function (e, t) {
            return this.filter(function (o) {
                return o[e] === t
            })
        }, e.prototype.filter = function (e) {
            var t = [];
            return this.iterate(function (o) {
                return e(o) && t.push(o), !0
            }), t
        }, e.prototype.getNextNode = function (e) {
            if (void 0 === e && (e = !0), e && this.hasChildren() && this.is_open) return this.children[0];
            if (this.parent) {
                var t = this.getNextSibling();
                return t || this.parent.getNextNode(!1)
            }
            return null
        }, e.prototype.getPreviousNode = function () {
            if (this.parent) {
                var e = this.getPreviousSibling();
                return e ? e.hasChildren() && e.is_open ? e.getLastChild() : e : this.getParent()
            }
            return null
        }, e.prototype.getParent = function () {
            return this.parent && this.parent.parent ? this.parent : null
        }, e.prototype.getLastChild = function () {
            if (this.hasChildren()) {
                var e = this.children[this.children.length - 1];
                return e.hasChildren() && e.is_open ? e.getLastChild() : e
            }
            return null
        }, e.prototype.initFromData = function (e) {
            var t, o = this, n = function (e) {
                for (var t = 0, n = e; t < n.length; t++) {
                    var r = n[t], i = new o.tree.node_class("");
                    i.initFromData(r), o.addChild(i)
                }
            };
            t = e, o.setData(t), t.children && n(t.children)
        }, e.prototype._setParent = function (e) {
            this.parent = e, this.tree = e.tree, this.tree.addNodeToIndex(this)
        }, e.prototype._removeChild = function (e) {
            this.children.splice(this.getChildIndex(e), 1), this.tree.removeNodeFromIndex(e)
        }, e
    }();
    t.Node = r
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0, t.isInt = function (e) {
        return "number" == typeof e && e % 1 == 0
    }, t.isFunction = function (e) {
        return "function" == typeof e
    }, t.html_escape = function (e) {
        return ("" + e).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;").replace(/\//g, "&#x2F;")
    }, t.getBoolString = function (e) {
        return e ? "true" : "false"
    }
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0;
    var n = function () {
        function e(e, t) {
            this.$el = jQuery(e);
            var o = this.constructor.defaults;
            this.options = jQuery.extend({}, o, t)
        }

        return e.register = function (t, o) {
            var n = function () {
                return "simple_widget_" + o
            };

            function r(t, o) {
                var n = jQuery.data(t, o);
                return n && n instanceof e ? n : null
            }

            jQuery.fn[o] = function (o) {
                for (var i = [], s = 1; s < arguments.length; s++) i[s - 1] = arguments[s];
                if (void 0 === o || "object" == typeof o) return function (e, o) {
                    for (var i = n(), s = 0, a = e.get(); s < a.length; s++) {
                        var l = a[s];
                        if (!r(l, i)) {
                            var d = new t(l, o);
                            jQuery.data(l, i) || jQuery.data(l, i, d), d._init()
                        }
                    }
                    return e
                }(this, o);
                if ("string" == typeof o && "_" !== o[0]) {
                    var a = o;
                    return "destroy" === a ? function (e) {
                        for (var t = n(), o = 0, i = e.get(); o < i.length; o++) {
                            var s = i[o], a = r(s, t);
                            a && a.destroy(), jQuery.removeData(s, t)
                        }
                    }(this) : "get_widget_class" === a ? t : function (t, o, r) {
                        for (var i = null, s = 0, a = t.get(); s < a.length; s++) {
                            var l = a[s], d = jQuery.data(l, n());
                            if (d && d instanceof e) {
                                var h = d[o];
                                h && "function" == typeof h && (i = h.apply(d, r))
                            }
                        }
                        return i
                    }(this, a, i)
                }
            }
        }, e.prototype.destroy = function () {
            this._deinit()
        }, e.prototype._init = function () {
        }, e.prototype._deinit = function () {
        }, e.defaults = {}, e
    }();
    t.default = n
}, function (e, t) {
    e.exports = jQuery
}, function (e, t, o) {
    "use strict";
    var n,
        r = this && this.__extends || (n = Object.setPrototypeOf || {__proto__: []} instanceof Array && function (e, t) {
            e.__proto__ = t
        } || function (e, t) {
            for (var o in t) t.hasOwnProperty(o) && (e[o] = t[o])
        }, function (e, t) {
            function o() {
                this.constructor = e
            }

            n(e, t), e.prototype = null === t ? Object.create(t) : (o.prototype = t.prototype, new o)
        });
    t.__esModule = !0;
    var i = o(0), s = function () {
        function e(e, t) {
            this.init(e, t)
        }

        return e.prototype.init = function (e, t) {
            this.node = e, this.tree_widget = t, e.element || (e.element = this.tree_widget.element.get(0)), this.$element = jQuery(e.element)
        }, e.prototype.addDropHint = function (e) {
            return this.mustShowBorderDropHint(e) ? new l(this.$element, this.tree_widget._getScrollLeft()) : new d(this.node, this.$element, e)
        }, e.prototype.select = function (e) {
            var t = this.getLi();
            t.addClass("jqtree-selected"), t.attr("aria-selected", "true");
            var o = this.getSpan();
            o.attr("tabindex", this.tree_widget.options.tabIndex), e && o.focus()
        }, e.prototype.deselect = function () {
            var e = this.getLi();
            e.removeClass("jqtree-selected"), e.attr("aria-selected", "false");
            var t = this.getSpan();
            t.removeAttr("tabindex"), t.blur()
        }, e.prototype.getUl = function () {
            return this.$element.children("ul:first")
        }, e.prototype.getSpan = function () {
            return this.$element.children(".jqtree-element").find("span.jqtree-title")
        }, e.prototype.getLi = function () {
            return this.$element
        }, e.prototype.mustShowBorderDropHint = function (e) {
            return e === i.Position.Inside
        }, e
    }();
    t.NodeElement = s;
    var a = function (e) {
        function t() {
            return null !== e && e.apply(this, arguments) || this
        }

        return r(t, e), t.prototype.open = function (e, t, o) {
            var n = this;
            if (void 0 === t && (t = !0), void 0 === o && (o = "fast"), !this.node.is_open) {
                this.node.is_open = !0;
                var r = this.getButton();
                r.removeClass("jqtree-closed"), r.html("");
                var i = r.get(0);
                if (i) {
                    var s = this.tree_widget.renderer.opened_icon_element.cloneNode(!1);
                    i.appendChild(s)
                }
                var a = function () {
                    n.getLi().removeClass("jqtree-closed"), n.getSpan().attr("aria-expanded", "true"), e && e(n.node), n.tree_widget._triggerEvent("tree.open", {node: n.node})
                };
                t ? this.getUl().slideDown(o, a) : (this.getUl().show(), a())
            }
        }, t.prototype.close = function (e, t) {
            var o = this;
            if (void 0 === e && (e = !0), void 0 === t && (t = "fast"), this.node.is_open) {
                this.node.is_open = !1;
                var n = this.getButton();
                n.addClass("jqtree-closed"), n.html("");
                var r = n.get(0);
                if (r) {
                    var i = this.tree_widget.renderer.closed_icon_element.cloneNode(!1);
                    r.appendChild(i)
                }
                var s = function () {
                    o.getLi().addClass("jqtree-closed"), o.getSpan().attr("aria-expanded", "false"), o.tree_widget._triggerEvent("tree.close", {node: o.node})
                };
                e ? this.getUl().slideUp(t, s) : (this.getUl().hide(), s())
            }
        }, t.prototype.mustShowBorderDropHint = function (e) {
            return !this.node.is_open && e === i.Position.Inside
        }, t.prototype.getButton = function () {
            return this.$element.children(".jqtree-element").find("a.jqtree-toggler")
        }, t
    }(s);
    t.FolderElement = a;
    var l = function () {
        function e(e, t) {
            var o = e.children(".jqtree-element"), n = e.width() || 0, r = Math.max(n + t - 4, 0),
                i = o.outerHeight() || 0, s = Math.max(i - 4, 0);
            this.$hint = jQuery('<span class="jqtree-border"></span>'), o.append(this.$hint), this.$hint.css({
                width: r,
                height: s
            })
        }

        return e.prototype.remove = function () {
            this.$hint.remove()
        }, e
    }();
    t.BorderDropHint = l;
    var d = function () {
        function e(e, t, o) {
            this.$element = t, this.node = e, this.$ghost = jQuery('<li class="jqtree_common jqtree-ghost"><span class="jqtree_common jqtree-circle"></span>\n            <span class="jqtree_common jqtree-line"></span></li>'), o === i.Position.After ? this.moveAfter() : o === i.Position.Before ? this.moveBefore() : o === i.Position.Inside && (e.isFolder() && e.is_open ? this.moveInsideOpenFolder() : this.moveInside())
        }

        return e.prototype.remove = function () {
            this.$ghost.remove()
        }, e.prototype.moveAfter = function () {
            this.$element.after(this.$ghost)
        }, e.prototype.moveBefore = function () {
            this.$element.before(this.$ghost)
        }, e.prototype.moveInsideOpenFolder = function () {
            jQuery(this.node.children[0].element).before(this.$ghost)
        }, e.prototype.moveInside = function () {
            this.$element.after(this.$ghost), this.$ghost.addClass("jqtree-inside")
        }, e
    }()
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0;
    var n = function () {
        function e(e) {
            this.tree_widget = e, this.clear()
        }

        return e.prototype.getSelectedNode = function () {
            var e = this.getSelectedNodes();
            return !!e.length && e[0]
        }, e.prototype.getSelectedNodes = function () {
            if (this.selected_single_node) return [this.selected_single_node];
            var e = [];
            for (var t in this.selected_nodes) if (this.selected_nodes.hasOwnProperty(t)) {
                var o = this.tree_widget.getNodeById(t);
                o && e.push(o)
            }
            return e
        }, e.prototype.getSelectedNodesUnder = function (e) {
            if (this.selected_single_node) return e.isParentOf(this.selected_single_node) ? [this.selected_single_node] : [];
            var t = [];
            for (var o in this.selected_nodes) if (this.selected_nodes.hasOwnProperty(o)) {
                var n = this.tree_widget.getNodeById(o);
                n && e.isParentOf(n) && t.push(n)
            }
            return t
        }, e.prototype.isNodeSelected = function (e) {
            return !!e && (null != e.id ? !!this.selected_nodes[e.id] : !!this.selected_single_node && this.selected_single_node.element === e.element)
        }, e.prototype.clear = function () {
            this.selected_nodes = {}, this.selected_single_node = null
        }, e.prototype.removeFromSelection = function (e, t) {
            var o = this;
            void 0 === t && (t = !1), null == e.id ? this.selected_single_node && e.element === this.selected_single_node.element && (this.selected_single_node = null) : (delete this.selected_nodes[e.id], t && e.iterate(function () {
                return delete o.selected_nodes[e.id], !0
            }))
        }, e.prototype.addToSelection = function (e) {
            null != e.id ? this.selected_nodes[e.id] = !0 : this.selected_single_node = e
        }, e
    }();
    t.default = n
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0;
    var n = function () {
        function e(e) {
            this.tree_widget = e, this.previous_top = -1, this.is_initialized = !1
        }

        return e.prototype.checkScrolling = function () {
            this.ensureInit(), this.checkVerticalScrolling(), this.checkHorizontalScrolling()
        }, e.prototype.scrollToY = function (e) {
            if (this.ensureInit(), this.$scroll_parent) this.$scroll_parent[0].scrollTop = e; else {
                var t = this.tree_widget.$el.offset(), o = t ? t.top : 0;
                jQuery(document).scrollTop(e + o)
            }
        }, e.prototype.isScrolledIntoView = function (e) {
            var t, o, n, r;
            this.ensureInit();
            var i, s = e.height() || 0;
            this.$scroll_parent ? (r = 0, o = this.$scroll_parent.height() || 0, t = (n = ((i = e.offset()) ? i.top : 0) - this.scroll_parent_top) + s) : (o = (r = jQuery(window).scrollTop() || 0) + (jQuery(window).height() || 0), t = (n = (i = e.offset()) ? i.top : 0) + s);
            return t <= o && n >= r
        }, e.prototype.getScrollLeft = function () {
            return this.$scroll_parent && this.$scroll_parent.scrollLeft() || 0
        }, e.prototype.initScrollParent = function () {
            var e = this, t = function () {
                e.scroll_parent_top = 0, e.$scroll_parent = null
            };
            "fixed" === this.tree_widget.$el.css("position") && t();
            var o = function () {
                var t = ["overflow", "overflow-y"], o = function (e) {
                    for (var o = 0, n = t; o < n.length; o++) {
                        var r = n[o], i = e.css(r);
                        if ("auto" === i || "scroll" === i) return !0
                    }
                    return !1
                };
                if (o(e.tree_widget.$el)) return e.tree_widget.$el;
                for (var n = 0, r = e.tree_widget.$el.parents().get(); n < r.length; n++) {
                    var i = r[n], s = jQuery(i);
                    if (o(s)) return s
                }
                return null
            }();
            if (o && o.length && "HTML" !== o[0].tagName) {
                this.$scroll_parent = o;
                var n = this.$scroll_parent.offset();
                this.scroll_parent_top = n ? n.top : 0
            } else t();
            this.is_initialized = !0
        }, e.prototype.ensureInit = function () {
            this.is_initialized || this.initScrollParent()
        }, e.prototype.handleVerticalScrollingWithScrollParent = function (e) {
            var t = this.$scroll_parent && this.$scroll_parent[0];
            t && (this.scroll_parent_top + t.offsetHeight - e.bottom < 20 ? (t.scrollTop += 20, this.tree_widget.refreshHitAreas(), this.previous_top = -1) : e.top - this.scroll_parent_top < 20 && (t.scrollTop -= 20, this.tree_widget.refreshHitAreas(), this.previous_top = -1))
        }, e.prototype.handleVerticalScrollingWithDocument = function (e) {
            var t = jQuery(document).scrollTop() || 0;
            e.top - t < 20 ? jQuery(document).scrollTop(t - 20) : (jQuery(window).height() || 0) - (e.bottom - t) < 20 && jQuery(document).scrollTop(t + 20)
        }, e.prototype.checkVerticalScrolling = function () {
            var e = this.tree_widget.dnd_handler && this.tree_widget.dnd_handler.hovered_area;
            e && e.top !== this.previous_top && (this.previous_top = e.top, this.$scroll_parent ? this.handleVerticalScrollingWithScrollParent(e) : this.handleVerticalScrollingWithDocument(e))
        }, e.prototype.checkHorizontalScrolling = function () {
            var e = this.tree_widget.dnd_handler && this.tree_widget.dnd_handler.position_info;
            e && (this.$scroll_parent ? this.handleHorizontalScrollingWithParent(e) : this.handleHorizontalScrollingWithDocument(e))
        }, e.prototype.handleHorizontalScrollingWithParent = function (e) {
            var t = this.$scroll_parent, o = t && t.offset();
            if (t && o) {
                var n = t[0], r = n.scrollLeft + n.clientWidth < n.scrollWidth, i = n.scrollLeft > 0,
                    s = o.left + n.clientWidth, a = o.left, l = e.page_x > s - 20, d = e.page_x < a + 20;
                l && r ? n.scrollLeft = Math.min(n.scrollLeft + 20, n.scrollWidth) : d && i && (n.scrollLeft = Math.max(n.scrollLeft - 20, 0))
            }
        }, e.prototype.handleHorizontalScrollingWithDocument = function (e) {
            var t = jQuery(document), o = t.scrollLeft() || 0, n = jQuery(window).width() || 0, r = o > 0,
                i = e.page_x > n - 20, s = e.page_x - o < 20;
            i ? t.scrollLeft(o + 20) : s && r && t.scrollLeft(Math.max(o - 20, 0))
        }, e
    }();
    t.default = n
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0;
    var n = o(1), r = function () {
        function e(e) {
            this.tree_widget = e
        }

        return e.prototype.saveState = function () {
            var e = JSON.stringify(this.getState());
            this.tree_widget.options.onSetStateFromStorage ? this.tree_widget.options.onSetStateFromStorage(e) : this.supportsLocalStorage() && localStorage.setItem(this.getKeyName(), e)
        }, e.prototype.getStateFromStorage = function () {
            var e = this._loadFromStorage();
            return e ? this._parseState(e) : null
        }, e.prototype.getState = function () {
            var e, t = this;
            return {
                open_nodes: (e = [], t.tree_widget.tree.iterate(function (t) {
                    return t.is_open && t.id && t.hasChildren() && e.push(t.id), !0
                }), e), selected_node: t.tree_widget.getSelectedNodes().map(function (e) {
                    return e.id
                })
            }
        }, e.prototype.setInitialState = function (e) {
            if (e) {
                var t = !1;
                return e.open_nodes && (t = this._openInitialNodes(e.open_nodes)), e.selected_node && (this._resetSelection(), this._selectInitialNodes(e.selected_node)), t
            }
            return !1
        }, e.prototype.setInitialStateOnDemand = function (e, t) {
            e ? this._setInitialStateOnDemand(e.open_nodes, e.selected_node, t) : t()
        }, e.prototype.getNodeIdToBeSelected = function () {
            var e = this.getStateFromStorage();
            return e && e.selected_node ? e.selected_node[0] : null
        }, e.prototype._parseState = function (e) {
            var t = jQuery.parseJSON(e);
            return t && t.selected_node && n.isInt(t.selected_node) && (t.selected_node = [t.selected_node]), t
        }, e.prototype._loadFromStorage = function () {
            return this.tree_widget.options.onGetStateFromStorage ? this.tree_widget.options.onGetStateFromStorage() : this.supportsLocalStorage() ? localStorage.getItem(this.getKeyName()) : void 0
        }, e.prototype._openInitialNodes = function (e) {
            for (var t = !1, o = 0, n = e; o < n.length; o++) {
                var r = n[o], i = this.tree_widget.getNodeById(r);
                i && (i.load_on_demand ? t = !0 : i.is_open = !0)
            }
            return t
        }, e.prototype._selectInitialNodes = function (e) {
            for (var t = 0, o = 0, n = e; o < n.length; o++) {
                var r = n[o], i = this.tree_widget.getNodeById(r);
                i && (t += 1, this.tree_widget.select_node_handler && this.tree_widget.select_node_handler.addToSelection(i))
            }
            return 0 !== t
        }, e.prototype._resetSelection = function () {
            var e = this.tree_widget.select_node_handler;
            e && e.getSelectedNodes().forEach(function (t) {
                e.removeFromSelection(t)
            })
        }, e.prototype._setInitialStateOnDemand = function (e, t, o) {
            var n = this, r = 0, i = e, s = function () {
                for (var e = [], s = 0, l = i; s < l.length; s++) {
                    var d = l[s], h = n.tree_widget.getNodeById(d);
                    h ? h.is_loading || (h.load_on_demand ? a(h) : n.tree_widget._openNode(h, !1, null)) : e.push(d)
                }
                i = e, n._selectInitialNodes(t) && n.tree_widget._refreshElements(null), 0 === r && o()
            }, a = function (e) {
                r += 1, n.tree_widget._openNode(e, !1, function () {
                    r -= 1, s()
                })
            };
            s()
        }, e.prototype.getKeyName = function () {
            return "string" == typeof this.tree_widget.options.saveState ? this.tree_widget.options.saveState : "tree"
        }, e.prototype.supportsLocalStorage = function () {
            return null == this._supportsLocalStorage && (this._supportsLocalStorage = function () {
                if (null == localStorage) return !1;
                try {
                    var e = "_storage_test";
                    sessionStorage.setItem(e, "value"), sessionStorage.removeItem(e)
                } catch (e) {
                    return !1
                }
                return !0
            }()), this._supportsLocalStorage
        }, e
    }();
    t.default = r
}, function (e, t, o) {
    "use strict";
    var n,
        r = this && this.__extends || (n = Object.setPrototypeOf || {__proto__: []} instanceof Array && function (e, t) {
            e.__proto__ = t
        } || function (e, t) {
            for (var o in t) t.hasOwnProperty(o) && (e[o] = t[o])
        }, function (e, t) {
            function o() {
                this.constructor = e
            }

            n(e, t), e.prototype = null === t ? Object.create(t) : (o.prototype = t.prototype, new o)
        });
    t.__esModule = !0;
    var i = function (e) {
        function t() {
            var t = null !== e && e.apply(this, arguments) || this;
            return t.mouseDown = function (e) {
                if (1 === e.which) {
                    var o = t._handleMouseDown(t._getPositionInfo(e));
                    return o && e.preventDefault(), o
                }
            }, t.mouseMove = function (e) {
                return t._handleMouseMove(e, t._getPositionInfo(e))
            }, t.mouseUp = function (e) {
                return t._handleMouseUp(t._getPositionInfo(e))
            }, t.touchStart = function (e) {
                var o = e.originalEvent;
                if (!(o.touches.length > 1)) {
                    var n = o.changedTouches[0];
                    return t._handleMouseDown(t._getPositionInfo(n))
                }
            }, t.touchMove = function (e) {
                var o = e.originalEvent;
                if (!(o.touches.length > 1)) {
                    var n = o.changedTouches[0];
                    return t._handleMouseMove(e, t._getPositionInfo(n))
                }
            }, t.touchEnd = function (e) {
                var o = e.originalEvent;
                if (!(o.touches.length > 1)) {
                    var n = o.changedTouches[0];
                    return t._handleMouseUp(t._getPositionInfo(n))
                }
            }, t
        }

        return r(t, e), t.prototype.setMouseDelay = function (e) {
            this.mouse_delay = e
        }, t.prototype._init = function () {
            this.$el.on("mousedown.mousewidget", this.mouseDown), this.$el.on("touchstart.mousewidget", this.touchStart), this.is_mouse_started = !1, this.mouse_delay = 0, this._mouse_delay_timer = null, this._is_mouse_delay_met = !0, this.mouse_down_info = null
        }, t.prototype._deinit = function () {
            this.$el.off("mousedown.mousewidget"), this.$el.off("touchstart.mousewidget");
            var e = jQuery(document);
            e.off("mousemove.mousewidget"), e.off("mouseup.mousewidget")
        }, t.prototype._handleMouseDown = function (e) {
            if (this.is_mouse_started && this._handleMouseUp(e), this.mouse_down_info = e, this._mouseCapture(e)) return this._handleStartMouse(), !0
        }, t.prototype._handleStartMouse = function () {
            var e = jQuery(document);
            e.on("mousemove.mousewidget", this.mouseMove), e.on("touchmove.mousewidget", this.touchMove), e.on("mouseup.mousewidget", this.mouseUp), e.on("touchend.mousewidget", this.touchEnd), this.mouse_delay && this._startMouseDelayTimer()
        }, t.prototype._startMouseDelayTimer = function () {
            var e = this;
            this._mouse_delay_timer && clearTimeout(this._mouse_delay_timer), this._mouse_delay_timer = setTimeout(function () {
                e._is_mouse_delay_met = !0
            }, this.mouse_delay), this._is_mouse_delay_met = !1
        }, t.prototype._handleMouseMove = function (e, t) {
            return this.is_mouse_started ? (this._mouseDrag(t), e.preventDefault()) : !(!this.mouse_delay || this._is_mouse_delay_met) || (this.mouse_down_info && (this.is_mouse_started = !1 !== this._mouseStart(this.mouse_down_info)), this.is_mouse_started ? this._mouseDrag(t) : this._handleMouseUp(t), !this.is_mouse_started)
        }, t.prototype._getPositionInfo = function (e) {
            return {page_x: e.pageX, page_y: e.pageY, target: e.target, original_event: e}
        }, t.prototype._handleMouseUp = function (e) {
            var t = jQuery(document);
            t.off("mousemove.mousewidget"), t.off("touchmove.mousewidget"), t.off("mouseup.mousewidget"), t.off("touchend.mousewidget"), this.is_mouse_started && (this.is_mouse_started = !1, this._mouseStop(e))
        }, t
    }(o(2).default);
    t.default = i
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0;
    var n = function () {
        function e(t) {
            var o = this;
            this.handleKeyDown = function (t) {
                if (!o.canHandleKeyboard()) return !0;
                switch (t.which) {
                    case e.DOWN:
                        return o.moveDown();
                    case e.UP:
                        return o.moveUp();
                    case e.RIGHT:
                        return o.moveRight();
                    case e.LEFT:
                        return o.moveLeft();
                    default:
                        return !0
                }
            }, this.tree_widget = t, t.options.keyboardSupport && jQuery(document).on("keydown.jqtree", this.handleKeyDown)
        }

        return e.prototype.deinit = function () {
            jQuery(document).off("keydown.jqtree")
        }, e.prototype.moveDown = function () {
            var e = this.tree_widget.getSelectedNode();
            return !!e && this.selectNode(e.getNextNode())
        }, e.prototype.moveUp = function () {
            var e = this.tree_widget.getSelectedNode();
            return !!e && this.selectNode(e.getPreviousNode())
        }, e.prototype.moveRight = function () {
            var e = this.tree_widget.getSelectedNode();
            return !e || (!e.isFolder() || (e.is_open ? this.selectNode(e.getNextNode()) : (this.tree_widget.openNode(e), !1)))
        }, e.prototype.moveLeft = function () {
            var e = this.tree_widget.getSelectedNode();
            return !e || (e.isFolder() && e.is_open ? (this.tree_widget.closeNode(e), !1) : this.selectNode(e.getParent()))
        }, e.prototype.selectNode = function (e) {
            return !e || (this.tree_widget.selectNode(e), this.tree_widget.scroll_handler && !this.tree_widget.scroll_handler.isScrolledIntoView(jQuery(e.element).find(".jqtree-element")) && this.tree_widget.scrollToNode(e), !1)
        }, e.prototype.canHandleKeyboard = function () {
            return this.tree_widget.options.keyboardSupport && this.isFocusOnTree() && null != this.tree_widget.getSelectedNode()
        }, e.prototype.isFocusOnTree = function () {
            var e = document.activeElement;
            return e && "SPAN" === e.tagName && this.tree_widget._containsElement(e)
        }, e.LEFT = 37, e.UP = 38, e.RIGHT = 39, e.DOWN = 40, e
    }();
    t.default = n
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0;
    var n = o(1), r = function () {
        function e(e) {
            this.tree_widget = e, this.opened_icon_element = this.createButtonElement(e.options.openedIcon), this.closed_icon_element = this.createButtonElement(e.options.closedIcon)
        }

        return e.prototype.render = function (e) {
            e && e.parent ? this.renderFromNode(e) : this.renderFromRoot()
        }, e.prototype.renderFromRoot = function () {
            var e = this.tree_widget.element;
            e.empty(), this.createDomElements(e[0], this.tree_widget.tree.children, !0, 1)
        }, e.prototype.renderFromNode = function (e) {
            var t = jQuery(e.element), o = this.createLi(e, e.getLevel());
            this.attachNodeData(e, o), t.after(o), t.remove(), e.children && this.createDomElements(o, e.children, !1, e.getLevel() + 1)
        }, e.prototype.createDomElements = function (e, t, o, n) {
            var r = this.createUl(o);
            e.appendChild(r);
            for (var i = 0, s = t; i < s.length; i++) {
                var a = s[i], l = this.createLi(a, n);
                r.appendChild(l), this.attachNodeData(a, l), a.hasChildren() && this.createDomElements(l, a.children, !1, n + 1)
            }
        }, e.prototype.attachNodeData = function (e, t) {
            e.element = t, jQuery(t).data("node", e)
        }, e.prototype.createUl = function (e) {
            var t, o;
            e ? (t = "jqtree-tree", o = "tree", this.tree_widget.options.rtl && (t += " jqtree-rtl")) : (t = "", o = "group");
            var n = document.createElement("ul");
            return n.className = "jqtree_common " + t, n.setAttribute("role", o), n
        }, e.prototype.createLi = function (e, t) {
            var o = Boolean(this.tree_widget.select_node_handler && this.tree_widget.select_node_handler.isNodeSelected(e)),
                n = e.isFolder() ? this.createFolderLi(e, t, o) : this.createNodeLi(e, t, o);
            return this.tree_widget.options.onCreateLi && this.tree_widget.options.onCreateLi(e, jQuery(n), o), n
        }, e.prototype.createFolderLi = function (e, t, o) {
            var n = this.getButtonClasses(e), r = this.getFolderClasses(e, o),
                i = e.is_open ? this.opened_icon_element : this.closed_icon_element, s = document.createElement("li");
            s.className = "jqtree_common " + r, s.setAttribute("role", "presentation");
            var a = document.createElement("div");
            a.className = "jqtree-element jqtree_common", a.setAttribute("role", "presentation"), s.appendChild(a);
            var l = document.createElement("a");
            return l.className = n, l.appendChild(i.cloneNode(!0)), l.setAttribute("role", "presentation"), l.setAttribute("aria-hidden", "true"), this.tree_widget.options.buttonLeft && a.appendChild(l), a.appendChild(this.createTitleSpan(e.name, t, o, e.is_open, !0)), this.tree_widget.options.buttonLeft || a.appendChild(l), s
        }, e.prototype.createNodeLi = function (e, t, o) {
            var n = ["jqtree_common"];
            o && n.push("jqtree-selected");
            var r = n.join(" "), i = document.createElement("li");
            i.className = r, i.setAttribute("role", "presentation");
            var s = document.createElement("div");
            return s.className = "jqtree-element jqtree_common", s.setAttribute("role", "presentation"), i.appendChild(s), s.appendChild(this.createTitleSpan(e.name, t, o, e.is_open, !1)), i
        }, e.prototype.createTitleSpan = function (e, t, o, r, i) {
            var s = document.createElement("span"), a = "jqtree-title jqtree_common";
            return i && (a += " jqtree-title-folder"), s.className = a, s.setAttribute("role", "treeitem"), s.setAttribute("aria-level", "" + t), s.setAttribute("aria-selected", n.getBoolString(o)), s.setAttribute("aria-expanded", n.getBoolString(r)), o && s.setAttribute("tabindex", this.tree_widget.options.tabIndex), s.innerHTML = this.escapeIfNecessary(e), s
        }, e.prototype.getButtonClasses = function (e) {
            var t = ["jqtree-toggler", "jqtree_common"];
            return e.is_open || t.push("jqtree-closed"), this.tree_widget.options.buttonLeft ? t.push("jqtree-toggler-left") : t.push("jqtree-toggler-right"), t.join(" ")
        }, e.prototype.getFolderClasses = function (e, t) {
            var o = ["jqtree-folder"];
            return e.is_open || o.push("jqtree-closed"), t && o.push("jqtree-selected"), e.is_loading && o.push("jqtree-loading"), o.join(" ")
        }, e.prototype.escapeIfNecessary = function (e) {
            return this.tree_widget.options.autoEscape ? n.html_escape(e) : e
        }, e.prototype.createButtonElement = function (e) {
            if ("string" == typeof e) {
                var t = document.createElement("div");
                return t.innerHTML = e, document.createTextNode(t.innerHTML)
            }
            return jQuery(e)[0]
        }, e
    }();
    t.default = r
}, function (e, t, o) {
    "use strict";
    var n,
        r = this && this.__extends || (n = Object.setPrototypeOf || {__proto__: []} instanceof Array && function (e, t) {
            e.__proto__ = t
        } || function (e, t) {
            for (var o in t) t.hasOwnProperty(o) && (e[o] = t[o])
        }, function (e, t) {
            function o() {
                this.constructor = e
            }

            n(e, t), e.prototype = null === t ? Object.create(t) : (o.prototype = t.prototype, new o)
        });
    t.__esModule = !0;
    var i = o(3), s = o(0), a = o(1), l = function () {
        function e(e) {
            this.tree_widget = e, this.hovered_area = null, this.hit_areas = [], this.is_dragging = !1, this.current_item = null, this.position_info = null
        }

        return e.prototype.mouseCapture = function (e) {
            var t = i(e.target);
            if (!this.mustCaptureElement(t)) return null;
            if (this.tree_widget.options.onIsMoveHandle && !this.tree_widget.options.onIsMoveHandle(t)) return null;
            var o = this.tree_widget._getNodeElement(t);
            return o && this.tree_widget.options.onCanMove && (this.tree_widget.options.onCanMove(o.node) || (o = null)), this.current_item = o, null != this.current_item
        }, e.prototype.generateHitAreas = function () {
            if (this.current_item) {
                var e = new d(this.tree_widget.tree, this.current_item.node, this.getTreeDimensions().bottom);
                this.hit_areas = e.generate()
            } else this.hit_areas = []
        }, e.prototype.mouseStart = function (e) {
            if (this.current_item) {
                this.refresh();
                var t = i(e.target).offset(), o = t ? t.left : 0, n = t ? t.top : 0, r = this.current_item.node,
                    s = this.tree_widget.options.autoEscape ? a.html_escape(r.name) : r.name;
                return this.drag_element = new h(s, e.page_x - o, e.page_y - n, this.tree_widget.element), this.is_dragging = !0, this.position_info = e, this.current_item.$element.addClass("jqtree-moving"), !0
            }
            return !1
        }, e.prototype.mouseDrag = function (e) {
            if (this.current_item && this.drag_element) {
                this.drag_element.move(e.page_x, e.page_y), this.position_info = e;
                var t = this.findHoveredArea(e.page_x, e.page_y);
                return this.canMoveToArea(t) && t ? (t.node.isFolder() || this.stopOpenFolderTimer(), this.hovered_area !== t && (this.hovered_area = t, this.mustOpenFolderTimer(t) ? this.startOpenFolderTimer(t.node) : this.stopOpenFolderTimer(), this.updateDropHint())) : (this.removeHover(), this.removeDropHint(), this.stopOpenFolderTimer()), t || this.tree_widget.options.onDragMove && this.tree_widget.options.onDragMove(this.current_item.node, e.original_event), !0
            }
            return !1
        }, e.prototype.mouseStop = function (e) {
            this.moveItem(e), this.clear(), this.removeHover(), this.removeDropHint(), this.removeHitAreas();
            var t = this.current_item;
            return this.current_item && (this.current_item.$element.removeClass("jqtree-moving"), this.current_item = null), this.is_dragging = !1, this.position_info = null, !this.hovered_area && t && this.tree_widget.options.onDragStop && this.tree_widget.options.onDragStop(t.node, e.original_event), !1
        }, e.prototype.refresh = function () {
            this.removeHitAreas(), this.current_item && (this.generateHitAreas(), this.current_item = this.tree_widget._getNodeElementForNode(this.current_item.node), this.is_dragging && this.current_item.$element.addClass("jqtree-moving"))
        }, e.prototype.mustCaptureElement = function (e) {
            return !e.is("input,select,textarea")
        }, e.prototype.canMoveToArea = function (e) {
            if (e && this.current_item) {
                if (this.tree_widget.options.onCanMoveTo) {
                    var t = s.getPositionName(e.position);
                    return this.tree_widget.options.onCanMoveTo(this.current_item.node, e.node, t)
                }
                return !0
            }
            return !1
        }, e.prototype.removeHitAreas = function () {
            this.hit_areas = []
        }, e.prototype.clear = function () {
            this.drag_element && (this.drag_element.remove(), this.drag_element = null)
        }, e.prototype.removeDropHint = function () {
            this.previous_ghost && this.previous_ghost.remove()
        }, e.prototype.removeHover = function () {
            this.hovered_area = null
        }, e.prototype.findHoveredArea = function (e, t) {
            var o = this.getTreeDimensions();
            if (e < o.left || t < o.top || e > o.right || t > o.bottom) return null;
            for (var n = 0, r = this.hit_areas.length; n < r;) {
                var i = n + r >> 1, s = this.hit_areas[i];
                if (t < s.top) r = i; else {
                    if (!(t > s.bottom)) return s;
                    n = i + 1
                }
            }
            return null
        }, e.prototype.mustOpenFolderTimer = function (e) {
            var t = e.node;
            return t.isFolder() && !t.is_open && e.position === s.Position.Inside
        }, e.prototype.updateDropHint = function () {
            if (this.hovered_area) {
                this.removeDropHint();
                var e = this.tree_widget._getNodeElementForNode(this.hovered_area.node);
                this.previous_ghost = e.addDropHint(this.hovered_area.position)
            }
        }, e.prototype.startOpenFolderTimer = function (e) {
            var t = this;
            this.stopOpenFolderTimer(), this.open_folder_timer = setTimeout(function () {
                t.tree_widget._openNode(e, t.tree_widget.options.slide, function () {
                    t.refresh(), t.updateDropHint()
                })
            }, this.tree_widget.options.openFolderDelay)
        }, e.prototype.stopOpenFolderTimer = function () {
            this.open_folder_timer && (clearTimeout(this.open_folder_timer), this.open_folder_timer = null)
        }, e.prototype.moveItem = function (e) {
            var t = this;
            if (this.current_item && this.hovered_area && this.hovered_area.position !== s.Position.None && this.canMoveToArea(this.hovered_area)) {
                var o = this.current_item.node, n = this.hovered_area.node, r = this.hovered_area.position,
                    i = o.parent;
                r === s.Position.Inside && (this.hovered_area.node.is_open = !0);
                var a = function () {
                    t.tree_widget.tree.moveNode(o, n, r), t.tree_widget.element.empty(), t.tree_widget._refreshElements(null)
                };
                this.tree_widget._triggerEvent("tree.move", {
                    move_info: {
                        moved_node: o,
                        target_node: n,
                        position: s.getPositionName(r),
                        previous_parent: i,
                        do_move: a,
                        original_event: e.original_event
                    }
                }).isDefaultPrevented() || a()
            }
        }, e.prototype.getTreeDimensions = function () {
            var e = this.tree_widget.element.offset();
            if (e) {
                var t = this.tree_widget.element, o = t.width() || 0, n = t.height() || 0,
                    r = e.left + this.tree_widget._getScrollLeft();
                return {left: r, top: e.top, right: r + o, bottom: e.top + n + 16}
            }
            return {left: 0, top: 0, right: 0, bottom: 0}
        }, e
    }();
    t.DragAndDropHandler = l;
    var d = function (e) {
        function t(t, o, n) {
            var r = e.call(this, t) || this;
            return r.current_node = o, r.tree_bottom = n, r
        }

        return r(t, e), t.prototype.generate = function () {
            return this.positions = [], this.last_top = 0, this.iterate(), this.generateHitAreas(this.positions)
        }, t.prototype.generateHitAreas = function (e) {
            for (var t = -1, o = [], n = [], r = 0, i = e; r < i.length; r++) {
                var s = i[r];
                s.top !== t && o.length && (o.length && this.generateHitAreasForGroup(n, o, t, s.top), t = s.top, o = []), o.push(s)
            }
            return this.generateHitAreasForGroup(n, o, t, this.tree_bottom), n
        }, t.prototype.handleOpenFolder = function (e, t) {
            return e !== this.current_node && (e.children[0] !== this.current_node && this.addPosition(e, s.Position.Inside, this.getTop(t)), !0)
        }, t.prototype.handleClosedFolder = function (e, t, o) {
            var n = this.getTop(o);
            e === this.current_node ? this.addPosition(e, s.Position.None, n) : (this.addPosition(e, s.Position.Inside, n), t !== this.current_node && this.addPosition(e, s.Position.After, n))
        }, t.prototype.handleFirstNode = function (e) {
            e !== this.current_node && this.addPosition(e, s.Position.Before, this.getTop(i(e.element)))
        }, t.prototype.handleAfterOpenFolder = function (e, t) {
            e === this.current_node || t === this.current_node ? this.addPosition(e, s.Position.None, this.last_top) : this.addPosition(e, s.Position.After, this.last_top)
        }, t.prototype.handleNode = function (e, t, o) {
            var n = this.getTop(o);
            e === this.current_node ? this.addPosition(e, s.Position.None, n) : this.addPosition(e, s.Position.Inside, n), t === this.current_node || e === this.current_node ? this.addPosition(e, s.Position.None, n) : this.addPosition(e, s.Position.After, n)
        }, t.prototype.getTop = function (e) {
            var t = e.offset();
            return t ? t.top : 0
        }, t.prototype.addPosition = function (e, t, o) {
            var n = {top: o, bottom: 0, node: e, position: t};
            this.positions.push(n), this.last_top = o
        }, t.prototype.generateHitAreasForGroup = function (e, t, o, n) {
            for (var r = Math.min(t.length, 4), i = Math.round((n - o) / r), s = o, a = 0; a < r;) {
                var l = t[a];
                e.push({top: s, bottom: s + i, node: l.node, position: l.position}), s += i, a += 1
            }
        }, t
    }(function () {
        function e(e) {
            this.tree = e
        }

        return e.prototype.iterate = function () {
            var e = this, t = !0, o = function (n, r) {
                var s = (n.is_open || !n.element) && n.hasChildren(), a = null;
                if (n.element) {
                    if (!(a = i(n.element)).is(":visible")) return;
                    t && (e.handleFirstNode(n), t = !1), n.hasChildren() ? n.is_open ? e.handleOpenFolder(n, a) || (s = !1) : e.handleClosedFolder(n, r, a) : e.handleNode(n, r, a)
                }
                if (s) {
                    var l = n.children.length;
                    n.children.forEach(function (e, t) {
                        o(n.children[t], t === l - 1 ? null : n.children[t + 1])
                    }), n.is_open && a && e.handleAfterOpenFolder(n, r)
                }
            };
            o(this.tree, null)
        }, e
    }());
    t.HitAreasGenerator = d;
    var h = function () {
        function e(e, t, o, n) {
            this.offset_x = t, this.offset_y = o, this.$element = i('<span class="jqtree-title jqtree-dragging">' + e + "</span>"), this.$element.css("position", "absolute"), n.append(this.$element)
        }

        return e.prototype.move = function (e, t) {
            this.$element.offset({left: e - this.offset_x, top: t - this.offset_y})
        }, e.prototype.remove = function () {
            this.$element.remove()
        }, e
    }()
}, function (e, t, o) {
    "use strict";
    t.__esModule = !0;
    t.default = "1.4.5"
}, function (e, t, o) {
    "use strict";
    var n,
        r = this && this.__extends || (n = Object.setPrototypeOf || {__proto__: []} instanceof Array && function (e, t) {
            e.__proto__ = t
        } || function (e, t) {
            for (var o in t) t.hasOwnProperty(o) && (e[o] = t[o])
        }, function (e, t) {
            function o() {
                this.constructor = e
            }

            n(e, t), e.prototype = null === t ? Object.create(t) : (o.prototype = t.prototype, new o)
        });
    t.__esModule = !0;
    var i = o(12), s = o(3), a = o(11), l = o(10), d = o(9), h = o(8), u = o(7), p = o(6), c = o(5), _ = o(2), f = o(0),
        g = o(1), m = o(4), v = function (e) {
            function t() {
                var t = null !== e && e.apply(this, arguments) || this;
                return t._handleClick = function (e) {
                    var o = t._getClickTarget(e.target);
                    if (o) if ("button" === o.type) t.toggle(o.node, t.options.slide), e.preventDefault(), e.stopPropagation(); else if ("label" === o.type) {
                        var n = o.node;
                        t._triggerEvent("tree.click", {
                            node: n,
                            click_event: e
                        }).isDefaultPrevented() || t._selectNode(n, !0)
                    }
                }, t._handleDblclick = function (e) {
                    var o = t._getClickTarget(e.target);
                    o && "label" === o.type && t._triggerEvent("tree.dblclick", {node: o.node, click_event: e})
                }, t._handleContextmenu = function (e) {
                    var o = s(e.target).closest("ul.jqtree-tree .jqtree-element");
                    if (o.length) {
                        var n = t._getNode(o);
                        if (n) return e.preventDefault(), e.stopPropagation(), t._triggerEvent("tree.contextmenu", {
                            node: n,
                            click_event: e
                        }), !1
                    }
                    return null
                }, t
            }

            return r(t, e), t.prototype.toggle = function (e, t) {
                var o = null == t ? this.options.slide : t;
                return e.is_open ? this.closeNode(e, o) : this.openNode(e, o), this.element
            }, t.prototype.getTree = function () {
                return this.tree
            }, t.prototype.selectNode = function (e) {
                return this._selectNode(e, !1), this.element
            }, t.prototype.getSelectedNode = function () {
                return !!this.select_node_handler && this.select_node_handler.getSelectedNode()
            }, t.prototype.toJson = function () {
                return JSON.stringify(this.tree.getData())
            }, t.prototype.loadData = function (e, t) {
                return this._loadData(e, t), this.element
            }, t.prototype.loadDataFromUrl = function (e, t, o) {
                return "string" == typeof e ? this._loadDataFromUrl(e, t, o) : this._loadDataFromUrl(null, e, t), this.element
            }, t.prototype.reload = function (e) {
                return this._loadDataFromUrl(null, null, e), this.element
            }, t.prototype.getNodeById = function (e) {
                return this.tree.getNodeById(e)
            }, t.prototype.getNodeByName = function (e) {
                return this.tree.getNodeByName(e)
            }, t.prototype.getNodesByProperty = function (e, t) {
                return this.tree.getNodesByProperty(e, t)
            }, t.prototype.getNodeByHtmlElement = function (e) {
                return this._getNode(s(e))
            }, t.prototype.getNodeByCallback = function (e) {
                return this.tree.getNodeByCallback(e)
            }, t.prototype.openNode = function (e, t, o) {
                var n = this, r = function () {
                    var e, r;
                    return g.isFunction(t) ? (e = t, r = null) : (r = t, e = o), null == r && (r = n.options.slide), [r, e]
                }(), i = r[0], s = r[1];
                return e && this._openNode(e, i, s), this.element
            }, t.prototype.closeNode = function (e, t) {
                var o = null == t ? this.options.slide : t;
                return e.isFolder() && (new m.FolderElement(e, this).close(o, this.options.animationSpeed), this._saveState()), this.element
            }, t.prototype.isDragging = function () {
                return !!this.dnd_handler && this.dnd_handler.is_dragging
            }, t.prototype.refreshHitAreas = function () {
                return this.dnd_handler && this.dnd_handler.refresh(), this.element
            }, t.prototype.addNodeAfter = function (e, t) {
                var o = t.addAfter(e);
                return o && this._refreshElements(t.parent), o
            }, t.prototype.addNodeBefore = function (e, t) {
                var o = t.addBefore(e);
                return o && this._refreshElements(t.parent), o
            }, t.prototype.addParentNode = function (e, t) {
                var o = t.addParent(e);
                return o && this._refreshElements(o.parent), o
            }, t.prototype.removeNode = function (e) {
                return e.parent && this.select_node_handler && (this.select_node_handler.removeFromSelection(e, !0), e.remove(), this._refreshElements(e.parent)), this.element
            }, t.prototype.appendNode = function (e, t) {
                var o = t || this.tree, n = o.append(e);
                return this._refreshElements(o), n
            }, t.prototype.prependNode = function (e, t) {
                var o = t || this.tree, n = o.prepend(e);
                return this._refreshElements(o), n
            }, t.prototype.updateNode = function (e, t) {
                var o = t.id && t.id !== e.id;
                return o && this.tree.removeNodeFromIndex(e), e.setData(t), o && this.tree.addNodeToIndex(e), "object" == typeof t && t.children && (e.removeChildren(), t.children.length && e.loadFromData(t.children)), this.renderer.renderFromNode(e), this._selectCurrentNode(), this.element
            }, t.prototype.moveNode = function (e, t, o) {
                var n = f.getPosition(o);
                return this.tree.moveNode(e, t, n), this._refreshElements(null), this.element
            }, t.prototype.getStateFromStorage = function () {
                if (this.save_state_handler) return this.save_state_handler.getStateFromStorage()
            }, t.prototype.addToSelection = function (e, t) {
                return void 0 === t && (t = !0), e && this.select_node_handler && (this.select_node_handler.addToSelection(e), this._getNodeElementForNode(e).select(t), this._saveState()), this.element
            }, t.prototype.getSelectedNodes = function () {
                return this.select_node_handler ? this.select_node_handler.getSelectedNodes() : []
            }, t.prototype.isNodeSelected = function (e) {
                return !!this.select_node_handler && this.select_node_handler.isNodeSelected(e)
            }, t.prototype.removeFromSelection = function (e) {
                return this.select_node_handler && (this.select_node_handler.removeFromSelection(e), this._getNodeElementForNode(e).deselect(), this._saveState()), this.element
            }, t.prototype.scrollToNode = function (e) {
                if (this.scroll_handler) {
                    var t = s(e.element).offset(), o = t ? t.top : 0, n = this.$el.offset(), r = o - (n ? n.top : 0);
                    this.scroll_handler.scrollToY(r)
                }
                return this.element
            }, t.prototype.getState = function () {
                if (this.save_state_handler) return this.save_state_handler.getState()
            }, t.prototype.setState = function (e) {
                return this.save_state_handler && (this.save_state_handler.setInitialState(e), this._refreshElements(null)), this.element
            }, t.prototype.setOption = function (e, t) {
                return this.options[e] = t, this.element
            }, t.prototype.moveDown = function () {
                return this.key_handler && this.key_handler.moveDown(), this.element
            }, t.prototype.moveUp = function () {
                return this.key_handler && this.key_handler.moveUp(), this.element
            }, t.prototype.getVersion = function () {
                return i.default
            }, t.prototype.testGenerateHitAreas = function (e) {
                return this.dnd_handler ? (this.dnd_handler.current_item = this._getNodeElementForNode(e), this.dnd_handler.generateHitAreas(), this.dnd_handler.hit_areas) : []
            }, t.prototype._triggerEvent = function (e, t) {
                var o = s.Event(e);
                return s.extend(o, t), this.element.trigger(o), o
            }, t.prototype._openNode = function (e, t, o) {
                var n = this;
                void 0 === t && (t = !0);
                var r = function (e, t, o) {
                    new m.FolderElement(e, n).open(o, t, n.options.animationSpeed)
                };
                if (e.isFolder()) if (e.load_on_demand) this._loadFolderOnDemand(e, t, o); else {
                    for (var i = e.parent; i;) i.parent && r(i, !1, null), i = i.parent;
                    r(e, t, o), this._saveState()
                }
            }, t.prototype._refreshElements = function (e) {
                this.renderer.render(e), this._triggerEvent("tree.refresh")
            }, t.prototype._getNodeElementForNode = function (e) {
                return e.isFolder() ? new m.FolderElement(e, this) : new m.NodeElement(e, this)
            }, t.prototype._getNodeElement = function (e) {
                var t = this._getNode(e);
                return t ? this._getNodeElementForNode(t) : null
            }, t.prototype._containsElement = function (e) {
                var t = this._getNode(s(e));
                return null != t && t.tree === this.tree
            }, t.prototype._getScrollLeft = function () {
                return this.scroll_handler && this.scroll_handler.getScrollLeft() || 0
            }, t.prototype._init = function () {
                e.prototype._init.call(this), this.element = this.$el, this.mouse_delay = 300, this.is_initialized = !1, this.options.rtl = this._getRtlOption(), null === this.options.closedIcon && (this.options.closedIcon = this._getDefaultClosedIcon()), this.renderer = new l.default(this), null != u.default ? this.save_state_handler = new u.default(this) : this.options.saveState = !1, null != c.default && (this.select_node_handler = new c.default(this)), null != a.DragAndDropHandler ? this.dnd_handler = new a.DragAndDropHandler(this) : this.options.dragAndDrop = !1, null != p.default && (this.scroll_handler = new p.default(this)), null != d.default && null != c.default && (this.key_handler = new d.default(this)), this._initData(), this.element.click(this._handleClick), this.element.dblclick(this._handleDblclick), this.options.useContextMenu && this.element.on("contextmenu", this._handleContextmenu)
            }, t.prototype._deinit = function () {
                this.element.empty(), this.element.off(), this.key_handler && this.key_handler.deinit(), this.tree = new f.Node({}, !0), e.prototype._deinit.call(this)
            }, t.prototype._mouseCapture = function (e) {
                return !(!this.options.dragAndDrop || !this.dnd_handler) && this.dnd_handler.mouseCapture(e)
            }, t.prototype._mouseStart = function (e) {
                return !(!this.options.dragAndDrop || !this.dnd_handler) && this.dnd_handler.mouseStart(e)
            }, t.prototype._mouseDrag = function (e) {
                if (this.options.dragAndDrop && this.dnd_handler) {
                    var t = this.dnd_handler.mouseDrag(e);
                    return this.scroll_handler && this.scroll_handler.checkScrolling(), t
                }
                return !1
            }, t.prototype._mouseStop = function (e) {
                return !(!this.options.dragAndDrop || !this.dnd_handler) && this.dnd_handler.mouseStop(e)
            }, t.prototype._initData = function () {
                this.options.data ? this._loadData(this.options.data, null) : this._getDataUrlInfo(null) ? this._loadDataFromUrl(null, null, null) : this._loadData([], null)
            }, t.prototype._getDataUrlInfo = function (e) {
                var t = this, o = this.options.dataUrl || this.element.data("url");
                return "function" == typeof o ? o(e) : "string" == typeof o ? function () {
                    var n = {url: o};
                    if (e && e.id) {
                        var r = {node: e.id};
                        n.data = r
                    } else {
                        var i = t._getNodeIdToBeSelected();
                        i && (r = {selected_node: i}, n.data = r)
                    }
                    return n
                }() : o
            }, t.prototype._getNodeIdToBeSelected = function () {
                return this.options.saveState && this.save_state_handler ? this.save_state_handler.getNodeIdToBeSelected() : null
            }, t.prototype._initTree = function (e) {
                var t = this, o = function () {
                    t.is_initialized || (t.is_initialized = !0, t._triggerEvent("tree.init"))
                };
                this.tree = new this.options.nodeClass(null, !0, this.options.nodeClass), this.select_node_handler && this.select_node_handler.clear(), this.tree.loadFromData(e);
                var n = this._setInitialState();
                this._refreshElements(null), n ? this._setInitialStateOnDemand(o) : o()
            }, t.prototype._setInitialState = function () {
                var e = this, t = function () {
                    if (e.options.saveState && e.save_state_handler) {
                        var t = e.save_state_handler.getStateFromStorage();
                        return t ? [!0, e.save_state_handler.setInitialState(t)] : [!1, !1]
                    }
                    return [!1, !1]
                }(), o = t[0], n = t[1];
                return o || (n = function () {
                    if (!1 === e.options.autoOpen) return !1;
                    var t = e._getAutoOpenMaxLevel(), o = !1;
                    return e.tree.iterate(function (e, n) {
                        return e.load_on_demand ? (o = !0, !1) : !!e.hasChildren() && (e.is_open = !0, n !== t)
                    }), o
                }()), n
            }, t.prototype._setInitialStateOnDemand = function (e) {
                var t, o, n, r = this;
                (function () {
                    if (r.options.saveState && r.save_state_handler) {
                        var t = r.save_state_handler.getStateFromStorage();
                        return !!t && (r.save_state_handler.setInitialStateOnDemand(t, e), !0)
                    }
                    return !1
                })() || (t = r._getAutoOpenMaxLevel(), o = 0, (n = function () {
                    r.tree.iterate(function (e, i) {
                        return e.load_on_demand ? (e.is_loading || function (e) {
                            o += 1, r._openNode(e, !1, function () {
                                o -= 1, n()
                            })
                        }(e), !1) : (r._openNode(e, !1, null), i !== t)
                    }), 0 === o && e()
                })())
            }, t.prototype._getAutoOpenMaxLevel = function () {
                return !0 === this.options.autoOpen ? -1 : parseInt(this.options.autoOpen, 10)
            }, t.prototype._getClickTarget = function (e) {
                var t = s(e), o = t.closest(".jqtree-toggler");
                if (o.length) {
                    if (n = this._getNode(o)) return {type: "button", node: n}
                } else {
                    var n, r = t.closest(".jqtree-element");
                    if (r.length) if (n = this._getNode(r)) return {type: "label", node: n}
                }
                return null
            }, t.prototype._getNode = function (e) {
                var t = e.closest("li.jqtree_common");
                return 0 === t.length ? null : t.data("node")
            }, t.prototype._saveState = function () {
                this.options.saveState && this.save_state_handler && this.save_state_handler.saveState()
            }, t.prototype._selectCurrentNode = function () {
                var e = this.getSelectedNode();
                if (e) {
                    var t = this._getNodeElementForNode(e);
                    t && t.select(!0)
                }
            }, t.prototype._deselectCurrentNode = function () {
                var e = this.getSelectedNode();
                e && this.removeFromSelection(e)
            }, t.prototype._getDefaultClosedIcon = function () {
                return this.options.rtl ? "&#x25c0;" : "&#x25ba;"
            }, t.prototype._getRtlOption = function () {
                if (null != this.options.rtl) return this.options.rtl;
                var e = this.element.data("rtl");
                return null != e && !1 !== e
            }, t.prototype._notifyLoading = function (e, t, o) {
                this.options.onLoading && this.options.onLoading(e, t, o)
            }, t.prototype._selectNode = function (e, t) {
                var o = this;
                if (void 0 === t && (t = !1), this.select_node_handler) {
                    var n = function () {
                        o.options.saveState && o.save_state_handler && o.save_state_handler.saveState()
                    };
                    if (!e) return this._deselectCurrentNode(), void n();
                    if (o.options.onCanSelectNode ? o.options.selectable && o.options.onCanSelectNode(e) : o.options.selectable) {
                        if (this.select_node_handler.isNodeSelected(e)) t && (this._deselectCurrentNode(), this._triggerEvent("tree.select", {
                            node: null,
                            previous_node: e
                        })); else {
                            var r = this.getSelectedNode();
                            this._deselectCurrentNode(), this.addToSelection(e), this._triggerEvent("tree.select", {
                                node: e,
                                deselected_node: r
                            }), (i = e.parent) && i.parent && !i.is_open && o.openNode(i, !1)
                        }
                        var i;
                        n()
                    }
                }
            }, t.prototype._loadData = function (e, t) {
                e && (this._triggerEvent("tree.load_data", {tree_data: e}), t ? (this._deselectNodes(t), this._loadSubtree(e, t)) : this._initTree(e), this.isDragging() && this.dnd_handler && this.dnd_handler.refresh())
            }, t.prototype._deselectNodes = function (e) {
                if (this.select_node_handler) for (var t = 0, o = this.select_node_handler.getSelectedNodesUnder(e); t < o.length; t++) {
                    var n = o[t];
                    this.select_node_handler.removeFromSelection(n)
                }
            }, t.prototype._loadSubtree = function (e, t) {
                t.loadFromData(e), t.load_on_demand = !1, t.is_loading = !1, this._refreshElements(t)
            }, t.prototype._loadDataFromUrl = function (e, t, o) {
                var n, r = this, i = null, a = e, l = function () {
                    i && (i.removeClass("jqtree-loading"), r._notifyLoading(!1, t, i))
                }, d = function (e) {
                    l(), r._loadData(e, t), o && "function" == typeof o && o()
                }, h = function (e) {
                    var t = function (e) {
                        return r.options.dataFilter ? r.options.dataFilter(e) : e
                    }(function (e) {
                        return e instanceof Array || "object" == typeof e ? e : null != e ? s.parseJSON(e) : []
                    }(e));
                    d(t)
                }, u = function (e) {
                    l(), r.options.onLoadFailed && r.options.onLoadFailed(e)
                };
                return e || (a = this._getDataUrlInfo(t)), (i = t ? s(t.element) : r.element).addClass("jqtree-loading"), r._notifyLoading(!0, t, i), a ? a instanceof Array ? void d(a) : (n = "string" == typeof a ? {url: a} : (a.method || (a.method = "get"), a), void s.ajax(s.extend({}, n, {
                    method: null != a.method ? a.method.toUpperCase() : "GET",
                    cache: !1,
                    dataType: "json",
                    success: h,
                    error: u
                }))) : void l()
            }, t.prototype._loadFolderOnDemand = function (e, t, o) {
                var n = this;
                void 0 === t && (t = !0), e.is_loading = !0, this._loadDataFromUrl(null, e, function () {
                    n._openNode(e, t, o)
                })
            }, t.defaults = {
                animationSpeed: "fast",
                autoOpen: !1,
                saveState: !1,
                dragAndDrop: !1,
                selectable: !0,
                useContextMenu: !0,
                onCanSelectNode: null,
                onSetStateFromStorage: null,
                onGetStateFromStorage: null,
                onCreateLi: null,
                onIsMoveHandle: null,
                onCanMove: null,
                onCanMoveTo: null,
                onLoadFailed: null,
                autoEscape: !0,
                dataUrl: null,
                closedIcon: null,
                openedIcon: "&#x25bc;",
                slide: !0,
                nodeClass: f.Node,
                dataFilter: null,
                keyboardSupport: !0,
                openFolderDelay: 500,
                rtl: !1,
                onDragMove: null,
                onDragStop: null,
                buttonLeft: !0,
                onLoading: null,
                tabIndex: 0
            }, t
        }(h.default);
    _.default.register(v, "tree")
}, , , , , , , , function (e, t, o) {
    e.exports = o(13)
}]);